// vulnerable_defi.tact — intentionally vulnerable DeFi contract for demo
// Use only for educational purposes

import "@stdlib/deploy";

struct PoolData {
    totalLiquidity: Int as uint128;
    totalShares: Int as uint128;
    owner: Address;
    fee: Int as uint16;  // basis points
}

message AddLiquidity {
    amount: Int as uint64;
}

message RemoveLiquidity {
    shares: Int as uint64;
}

message Swap {
    tokenIn: Address;
    amountIn: Int as uint64;
    minAmountOut: Int as uint64;
}

message EmergencyWithdraw {}

contract VulnerableDefiPool with Deployable {
    pool: PoolData;
    balances: map<Address, Int>;
    shares: map<Address, Int>;

    init(owner: Address, fee: Int) {
        self.pool = PoolData{
            totalLiquidity: 0,
            totalShares: 0,
            owner: owner,
            fee: fee,  // BUG: no validation, fee can be >10000 (>100%)
        };
    }

    // BUG: No access control, anyone can add liquidity on behalf of others
    receive(msg: AddLiquidity) {
        let sender: Address = sender();
        let amount: Int = msg.amount;
        
        // BUG: Integer overflow not checked
        self.pool.totalLiquidity = self.pool.totalLiquidity + amount;
        
        // BUG: Division by zero when totalShares == 0 and totalLiquidity != 0
        let newShares: Int = amount * self.pool.totalShares / self.pool.totalLiquidity;
        self.shares.set(sender, (self.shares.get(sender) ?? 0) + newShares);
        self.pool.totalShares = self.pool.totalShares + newShares;
    }

    // BUG: Reentrancy via async message before state update
    receive(msg: RemoveLiquidity) {
        let sender: Address = sender();
        let userShares: Int = self.shares.get(sender) ?? 0;
        
        // BUG: No check that msg.shares <= userShares
        let amount: Int = msg.shares * self.pool.totalLiquidity / self.pool.totalShares;
        
        // BUG: Send before state update (reentrancy)
        send(SendParameters{
            to: sender,
            value: amount,
            mode: SendRemainingBalance,  // BUG: SendRemainingBalance drains entire contract
            body: "withdrawal".asComment()
        });
        
        // State update AFTER send (too late!)
        self.shares.set(sender, userShares - msg.shares);
        self.pool.totalShares = self.pool.totalShares - msg.shares;
        self.pool.totalLiquidity = self.pool.totalLiquidity - amount;
    }

    // BUG: Price manipulation via single-tx liquidity
    receive(msg: Swap) {
        let amountIn: Int = msg.amountIn;
        let fee: Int = amountIn * self.pool.fee / 10000;
        let amountAfterFee: Int = amountIn - fee;
        
        // BUG: No slippage protection enforced (minAmountOut ignored)
        let amountOut: Int = amountAfterFee * self.pool.totalLiquidity / (self.pool.totalLiquidity + amountAfterFee);
        
        // BUG: No token address validation
        self.pool.totalLiquidity = self.pool.totalLiquidity + amountAfterFee;
        
        send(SendParameters{
            to: sender(),
            value: amountOut,
            mode: SendIgnoreErrors,  // BUG: Silent failures on send
            body: "swap_out".asComment()
        });
    }

    // BUG: Emergency withdraw has no timelock or multi-sig
    receive(_: EmergencyWithdraw) {
        // BUG: Only owner check, but no 2-of-N multisig for large amounts
        require(sender() == self.pool.owner, "not owner");
        
        // BUG: Drains ALL funds including user deposits
        send(SendParameters{
            to: self.pool.owner,
            value: 0,
            mode: SendRemainingBalance + SendDestroyIfZero,
            body: "emergency".asComment()
        });
    }

    get fun poolInfo(): PoolData {
        return self.pool;
    }
    
    // BUG: Missing getter for individual user balances
    // BUG: No event emissions for audit trail
}
