package commands

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"

	"github.com/Twigpine/twig/internal/client"
	"github.com/Twigpine/twig/internal/did"
	"github.com/Twigpine/twig/internal/evm"
	"github.com/Twigpine/twig/internal/identity"
)

// NodeStatus displays a status dashboard for the node.
func NodeStatus(nodeURL, dirOverride string) error {
	nodeURL = client.ResolveNodeURL(nodeURL)
	kp, _ := identity.LoadKeypair(dirOverride)
	c := client.New(nodeURL, kp)

	resp, err := c.Get("/")
	if err != nil {
		return fmt.Errorf("failed to connect to node at %s: %w", nodeURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("node returned HTTP %d", resp.StatusCode)
	}

	var info map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return fmt.Errorf("decoding node response: %w", err)
	}

	fmt.Println("── Node Status Dashboard ─────────────────────────────────────────")
	fmt.Printf("  URL:        %s\n", nodeURL)
	if d, ok := info["did"].(string); ok {
		fmt.Printf("  DID:        %s\n", d)
	}
	if v, ok := info["version"].(string); ok {
		fmt.Printf("  Version:    %s\n", v)
	}
	if peers, ok := info["peer_count"]; ok {
		fmt.Printf("  Peers:      %v\n", peers)
	}
	if repos, ok := info["repo_count"]; ok {
		fmt.Printf("  Repos:      %v\n", repos)
	}

	if kp != nil {
		callerDID := kp.DID()
		short := did.ShortDID(callerDID)
		fmt.Println("\n── Local Identity Context ────────────────────────────────────────")
		fmt.Printf("  Identity:   %s\n", callerDID)
		if agentResp, err := c.Get(fmt.Sprintf("/api/v1/agents/%s", callerDID)); err == nil {
			defer agentResp.Body.Close()
			if agentResp.StatusCode == http.StatusOK {
				var aInfo map[string]interface{}
				_ = json.NewDecoder(agentResp.Body).Decode(&aInfo)
				if ts, ok := aInfo["trust_score"].(float64); ok {
					fmt.Printf("  Trust:      %.2f\n", ts)
				}
				fmt.Println("  Status:     Registered on node")
			} else {
				fmt.Println("  Status:     Not registered on node (run `twig register`)")
			}
		}
		_ = short
	}

	return nil
}

// NodeTrust queries the trust score for a DID.
func NodeTrust(targetDID, nodeURL string) error {
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, nil)

	resp, err := c.Get(fmt.Sprintf("/api/v1/agents/%s", targetDID))
	if err != nil {
		return fmt.Errorf("fetching agent trust: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		fmt.Printf("DID %s is not registered on %s\n", targetDID, nodeURL)
		return nil
	}

	var info map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	score, _ := info["trust_score"].(float64)
	fmt.Printf("DID:   %s\n", targetDID)
	fmt.Printf("Trust: %.2f\n", score)
	return nil
}

// NodeResolve resolves a DID to its registered agent details.
func NodeResolve(targetDID, nodeURL string) error {
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, nil)

	resp, err := c.Get(fmt.Sprintf("/api/v1/agents/%s", targetDID))
	if err != nil {
		return fmt.Errorf("resolving agent: %w", err)
	}

	return PrintResponseOrError(resp)
}

// NodeOnchainStatus queries on-chain node staking status.
func NodeOnchainStatus(nodeURL, rpcURL, contractAddr, dirOverride string) error {
	if rpcURL == "" {
		rpcURL = evm.DefaultRPCURL
	}
	if contractAddr == "" {
		return fmt.Errorf("staking contract address required (set --contract)")
	}

	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}
	didHash := evm.Keccak256([]byte(kp.DID()))

	c := evm.NewClient(rpcURL)
	data := append(evm.EncodeFunctionSignature("getNodeInfo(bytes32)"), mustBytes32(didHash)...)
	res, err := c.EthCall(contractAddr, "0x"+hex.EncodeToString(data))
	if err != nil {
		return fmt.Errorf("getNodeInfo failed: %w", err)
	}

	info, err := decodeNodeInfo(res)
	if err != nil {
		return fmt.Errorf("decoding node info: %w", err)
	}

	fmt.Printf("On-chain status for %s\n\n", kp.DID())
	if info.operator == "0x0000000000000000000000000000000000000000" {
		fmt.Println("  Status: NOT REGISTERED")
		fmt.Println("  Run `twig node register --stake <amount>` to register.")
		return nil
	}
	fmt.Printf("  Operator wallet:  %s\n", info.operator)
	fmt.Printf("  Staked:           %s $GITLAWB\n", evm.WeiToTokens(info.stake))
	fmt.Printf("  HTTP URL:         %s\n", info.httpURL)
	fmt.Printf("  Last heartbeat:   %s (unix)\n", info.lastHeartbeat.String())
	fmt.Printf("  Registered:       %s (unix)\n", info.registeredAt.String())
	fmt.Printf("  Active flag:      %v\n", info.active)
	fmt.Printf("  Currently active: %v\n", info.currentlyActive)
	fmt.Printf("  Pending rewards:  %s $GITLAWB\n", evm.WeiToTokens(info.pendingRewards))
	if info.unstakeRequestAt.Sign() != 0 {
		fmt.Printf("  Unstake pending:  yes (requested at unix %s)\n", info.unstakeRequestAt.String())
	}
	return nil
}

type nodeInfo struct {
	operator         string
	httpURL          string
	stake            *big.Int
	lastHeartbeat    *big.Int
	registeredAt     *big.Int
	active           bool
	currentlyActive  bool
	pendingRewards   *big.Int
	unstakeRequestAt *big.Int
}

func decodeNodeInfo(data []byte) (*nodeInfo, error) {
	if len(data) < 9*32 {
		return nil, fmt.Errorf("getNodeInfo returned %d bytes, want >= 288", len(data))
	}
	httpURL, err := evm.DecodeString(data, 32)
	if err != nil {
		return nil, err
	}
	return &nodeInfo{
		operator:         evm.DecodeAddress(data, 0),
		httpURL:          httpURL,
		stake:            evm.DecodeUint256(data, 64),
		lastHeartbeat:    evm.DecodeUint256(data, 96),
		registeredAt:     evm.DecodeUint256(data, 128),
		active:           evm.DecodeBool(data, 160),
		currentlyActive:  evm.DecodeBool(data, 192),
		pendingRewards:   evm.DecodeUint256(data, 224),
		unstakeRequestAt: evm.DecodeUint256(data, 256),
	}, nil
}

func mustBytes32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out, b)
	return out
}

// stakingTx validates inputs and submits a staking-contract transaction,
// returning after the receipt confirms success.
func stakingTx(privateKey, rpcURL, contractAddr, dirOverride string, data []byte) (*evm.TxReceipt, [32]byte, error) {
	var didHash [32]byte
	if contractAddr == "" {
		return nil, didHash, fmt.Errorf("staking contract address required (set --contract)")
	}
	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return nil, didHash, err
	}
	copy(didHash[:], evm.Keccak256([]byte(kp.DID())))
	if rpcURL == "" {
		rpcURL = evm.DefaultRPCURL
	}
	receipt, err := evm.CallContract(rpcURL, privateKey, contractAddr, data)
	if err != nil {
		return nil, didHash, err
	}
	return receipt, didHash, nil
}

func stakingCallData(sig string, didHash [32]byte) []byte {
	hb, _ := evm.EncodeBytes32Param(didHash[:])
	return append(evm.EncodeFunctionSignature(sig), hb...)
}

// NodeRegisterOnchain registers a node on-chain with stake.
func NodeRegisterOnchain(stake uint64, httpURL, privateKey, rpcURL, contractAddr, tokenAddr, dirOverride string) error {
	if rpcURL == "" {
		rpcURL = evm.DefaultRPCURL
	}
	if contractAddr == "" {
		return fmt.Errorf("staking contract address required (set --contract)")
	}
	if tokenAddr == "" {
		return fmt.Errorf("token contract address required (set --token)")
	}
	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}
	d := kp.DID()
	didHash := evm.Keccak256([]byte(d))
	stakeWei := evm.TokensToWei(stake)

	operator, err := evm.PrivateKeyToAddress(privateKey)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}

	fmt.Println("Registering node on Base L2...")
	fmt.Printf("  DID:      %s\n", d)
	fmt.Printf("  Stake:    %d $GITLAWB\n", stake)
	fmt.Printf("  HTTP URL: %s\n", httpURL)
	fmt.Printf("  Network:  %s\n\n", rpcURL)

	c := evm.NewClient(rpcURL)

	// 1. Check token balance.
	balData := append(evm.EncodeFunctionSignature("balanceOf(address)"), mustEncodeAddress(operator)...)
	balRes, err := c.EthCall(tokenAddr, "0x"+hex.EncodeToString(balData))
	if err != nil {
		return fmt.Errorf("balanceOf failed: %w", err)
	}
	if evm.DecodeUint256(balRes, 0).Cmp(stakeWei) < 0 {
		return fmt.Errorf("insufficient $GITLAWB balance: have %s, need %d",
			evm.WeiToTokens(evm.DecodeUint256(balRes, 0)), stake)
	}

	// 2. Approve the staking contract if allowance is insufficient.
	allowData := append(evm.EncodeFunctionSignature("allowance(address,address)"),
		append(mustEncodeAddress(operator), mustEncodeAddress(contractAddr)...)...)
	allowRes, err := c.EthCall(tokenAddr, "0x"+hex.EncodeToString(allowData))
	if err != nil {
		return fmt.Errorf("allowance check failed: %w", err)
	}
	if evm.DecodeUint256(allowRes, 0).Cmp(stakeWei) < 0 {
		fmt.Printf("Approving %d $GITLAWB for staking contract...\n", stake)
		approveData := append(evm.EncodeFunctionSignature("approve(address,uint256)"),
			append(mustEncodeAddress(contractAddr), evm.EncodeUint256Param(stakeWei)...)...)
		receipt, err := evm.CallContract(rpcURL, privateKey, tokenAddr, approveData)
		if err != nil {
			return fmt.Errorf("approve failed: %w", err)
		}
		fmt.Printf("  approved: %s\n", receipt.TxHash)
	}

	// 3. Register the node.
	fmt.Printf("Registering node (staking %d $GITLAWB)...\n", stake)
	hb, _ := evm.EncodeBytes32Param(didHash)
	regData := append(evm.EncodeFunctionSignature("registerNode(bytes32,string,uint256)"), hb...)
	regData = append(regData, evm.EncodeStringParams(httpURL)...)
	regData = append(regData, evm.EncodeUint256Param(stakeWei)...)
	receipt, err := evm.CallContract(rpcURL, privateKey, contractAddr, regData)
	if err != nil {
		return fmt.Errorf("registerNode failed: %w", err)
	}

	fmt.Println()
	fmt.Println("✓ Node registered")
	fmt.Printf("  Tx:              %s\n", receipt.TxHash)
	fmt.Printf("  Operator wallet: %s\n", operator)
	return nil
}

func mustEncodeAddress(addr string) []byte {
	b, err := evm.EncodeAddressParam(addr)
	if err != nil {
		panic(err)
	}
	return b
}

// NodeHeartbeat submits a heartbeat transaction.
func NodeHeartbeat(privateKey, rpcURL, contractAddr, dirOverride string) error {
	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}
	fmt.Printf("Posting heartbeat for %s...\n", kp.DID())
	var didHash [32]byte
	copy(didHash[:], evm.Keccak256([]byte(kp.DID())))
	receipt, _, err := stakingTx(privateKey, rpcURL, contractAddr, dirOverride,
		stakingCallData("heartbeat(bytes32)", didHash))
	if err != nil {
		return fmt.Errorf("heartbeat failed: %w", err)
	}
	fmt.Printf("✓ heartbeat sent: %s\n", receipt.TxHash)
	return nil
}

// NodeClaim claims accumulated node operator rewards.
func NodeClaim(privateKey, rpcURL, contractAddr, dirOverride string) error {
	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}
	fmt.Printf("Claiming rewards for %s...\n", kp.DID())
	var didHash [32]byte
	copy(didHash[:], evm.Keccak256([]byte(kp.DID())))
	receipt, _, err := stakingTx(privateKey, rpcURL, contractAddr, dirOverride,
		stakingCallData("claimRewards(bytes32)", didHash))
	if err != nil {
		return fmt.Errorf("claimRewards failed: %w", err)
	}
	fmt.Printf("✓ rewards claimed: %s\n", receipt.TxHash)
	return nil
}

// NodeUnstakeRequest starts the 7-day cooldown for unstaking.
func NodeUnstakeRequest(privateKey, rpcURL, contractAddr, dirOverride string) error {
	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}
	fmt.Println("Requesting unstake (starts 7-day cooldown)...")
	var didHash [32]byte
	copy(didHash[:], evm.Keccak256([]byte(kp.DID())))
	receipt, _, err := stakingTx(privateKey, rpcURL, contractAddr, dirOverride,
		stakingCallData("requestUnstake(bytes32)", didHash))
	if err != nil {
		return fmt.Errorf("requestUnstake failed: %w", err)
	}
	fmt.Printf("✓ unstake requested: %s\n", receipt.TxHash)
	fmt.Println("  Run `twig node unstake` after 7 days to complete withdrawal.")
	return nil
}

// NodeUnstake completes the unstake after cooldown.
func NodeUnstake(privateKey, rpcURL, contractAddr, dirOverride string) error {
	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}
	fmt.Println("Completing unstake...")
	var didHash [32]byte
	copy(didHash[:], evm.Keccak256([]byte(kp.DID())))
	receipt, _, err := stakingTx(privateKey, rpcURL, contractAddr, dirOverride,
		stakingCallData("unstake(bytes32)", didHash))
	if err != nil {
		return fmt.Errorf("unstake failed: %w", err)
	}
	fmt.Printf("✓ unstake complete: %s\n", receipt.TxHash)
	return nil
}
