package commands

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Twigpine/twig/internal/did"
	"github.com/Twigpine/twig/internal/evm"
)

// NameResolve queries the on-chain name registry on Base L2.
func NameResolve(name, rpcURL, contractAddr string) error {
	if rpcURL == "" {
		rpcURL = evm.DefaultRPCURL
	}
	if contractAddr == "" {
		contractAddr = evm.DefaultNameRegistry
	}

	c := evm.NewClient(rpcURL)

	// resolve(string) -> (address owner, string did, uint256 registeredAt, uint256 updatedAt)
	selector := evm.EncodeFunctionSignature("resolve(string)")
	param := evm.EncodeStringParameter(name)
	data := append(selector, param...)

	res, err := c.EthCall(contractAddr, hex.EncodeToString(data))
	if err != nil {
		return fmt.Errorf("eth_call failed: %w", err)
	}

	if len(res) < 32 {
		fmt.Printf("Name '%s' is not registered.\n", name)
		return nil
	}

	owner := evm.DecodeAddress(res, 0)
	if owner == "0x0000000000000000000000000000000000000000" {
		fmt.Printf("Name '%s' is not registered.\n", name)
		return nil
	}

	targetDID, _ := evm.DecodeString(res, 32)
	registeredAt := evm.DecodeUint256(res, 64)
	updatedAt := evm.DecodeUint256(res, 96)

	fmt.Printf("Name:         %s\n", name)
	fmt.Printf("Owner:        %s\n", owner)
	fmt.Printf("DID:          %s\n", targetDID)
	fmt.Printf("Registered:   %v\n", registeredAt)
	fmt.Printf("Updated:      %v\n", updatedAt)

	return nil
}

// NameLookup reverse resolves a DID to its registered name.
func NameLookup(targetDID, rpcURL, contractAddr string) error {
	if rpcURL == "" {
		rpcURL = evm.DefaultRPCURL
	}
	if contractAddr == "" {
		contractAddr = evm.DefaultNameRegistry
	}

	c := evm.NewClient(rpcURL)

	// reverseLookup(string) -> (string name)
	selector := evm.EncodeFunctionSignature("reverseLookup(string)")
	param := evm.EncodeStringParameter(targetDID)
	data := append(selector, param...)

	res, err := c.EthCall(contractAddr, hex.EncodeToString(data))
	if err != nil {
		return fmt.Errorf("eth_call failed: %w", err)
	}

	name, _ := evm.DecodeString(res, 0)
	name = strings.TrimSpace(name)
	if name == "" {
		fmt.Printf("No name registered for DID: %s\n", targetDID)
		return nil
	}

	fmt.Printf("DID:  %s\n", targetDID)
	fmt.Printf("Name: %s\n", name)
	return nil
}

// NameAvailable checks whether a name is available.
func NameAvailable(name, rpcURL, contractAddr string) error {
	if rpcURL == "" {
		rpcURL = evm.DefaultRPCURL
	}
	if contractAddr == "" {
		contractAddr = evm.DefaultNameRegistry
	}

	c := evm.NewClient(rpcURL)

	// isAvailable(string) -> (bool)
	selector := evm.EncodeFunctionSignature("isAvailable(string)")
	param := evm.EncodeStringParameter(name)
	data := append(selector, param...)

	res, err := c.EthCall(contractAddr, hex.EncodeToString(data))
	if err != nil {
		return fmt.Errorf("eth_call failed: %w", err)
	}

	avail := evm.DecodeBool(res, 0)
	if avail {
		fmt.Printf("✓ '%s' is available\n", name)
	} else {
		fmt.Printf("✗ '%s' is already registered\n", name)
	}

	return nil
}

// NameResolveDID resolves a DID document from the on-chain DID registry.
func NameResolveDID(targetDID, rpcURL, contractAddr string) error {
	if rpcURL == "" {
		rpcURL = evm.DefaultRPCURL
	}
	if contractAddr == "" {
		contractAddr = evm.DefaultDIDRegistry
	}

	c := evm.NewClient(rpcURL)

	// resolve(string) -> (address owner, string document)
	selector := evm.EncodeFunctionSignature("resolve(string)")
	param := evm.EncodeStringParameter(targetDID)
	data := append(selector, param...)

	res, err := c.EthCall(contractAddr, hex.EncodeToString(data))
	if err != nil {
		return fmt.Errorf("eth_call failed: %w", err)
	}

	owner := evm.DecodeAddress(res, 0)
	doc, _ := evm.DecodeString(res, 32)

	if owner == "0x0000000000000000000000000000000000000000" {
		fmt.Printf("DID '%s' is not registered on-chain.\n", targetDID)
		return nil
	}

	fmt.Printf("DID:      %s\n", targetDID)
	fmt.Printf("Owner:    %s\n", owner)
	fmt.Printf("Document: %s\n", doc)
	return nil
}

// NameRegister submits the name registration transaction and waits for confirmation.
func NameRegister(name, privateKey, rpcURL, contractAddr, dirOverride string) error {
	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	if rpcURL == "" {
		rpcURL = evm.DefaultRPCURL
	}
	if contractAddr == "" {
		contractAddr = evm.DefaultNameRegistry
	}

	d := kp.DID()
	fmt.Println("Registering name on Base L2...")
	fmt.Printf("  Name:     %s\n", name)
	fmt.Printf("  DID:      %s\n", d)
	fmt.Printf("  Network:  %s\n", rpcURL)
	fmt.Printf("  Contract: %s\n\n", contractAddr)

	if privateKey == "" {
		return fmt.Errorf("private key required for on-chain write (set --private-key or ETH_PRIVATE_KEY)")
	}

	data := append(evm.EncodeFunctionSignature("register(string,string)"), evm.EncodeStringParams(name, d)...)
	receipt, err := evm.CallContract(rpcURL, privateKey, contractAddr, data)
	if err != nil {
		return fmt.Errorf("name registration failed: %w", err)
	}

	fmt.Println()
	fmt.Printf("✓ '%s' is yours on Base L2\n", name)
	fmt.Printf("  DID:   %s\n", d)
	fmt.Printf("  Block: %d\n", receipt.BlockNumber)
	fmt.Printf("  Tx:    %s\n", receipt.TxHash)
	return nil
}

// NameRegisterDID anchors a DID document on-chain and waits for confirmation.
func NameRegisterDID(privateKey, rpcURL, contractAddr, dirOverride string) error {
	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	if rpcURL == "" {
		rpcURL = evm.DefaultRPCURL
	}
	if contractAddr == "" {
		contractAddr = evm.DefaultDIDRegistry
	}

	d := kp.DID()
	doc := did.NewDIDDocument(d)
	docBytes, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encoding DID document: %w", err)
	}

	fmt.Println("Anchoring DID on Base L2...")
	fmt.Printf("  DID:      %s\n", d)
	fmt.Printf("  Network:  %s\n", rpcURL)
	fmt.Printf("  Contract: %s\n\n", contractAddr)

	if privateKey == "" {
		return fmt.Errorf("private key required for on-chain write (set --private-key or ETH_PRIVATE_KEY)")
	}

	data := append(evm.EncodeFunctionSignature("register(string,string)"), evm.EncodeStringParams(d, string(docBytes))...)
	receipt, err := evm.CallContract(rpcURL, privateKey, contractAddr, data)
	if err != nil {
		return fmt.Errorf("DID anchoring failed: %w", err)
	}

	fmt.Printf("✓ Anchored DID Document for %s\n", d)
	fmt.Printf("  Block: %d\n", receipt.BlockNumber)
	fmt.Printf("  Tx:    %s\n", receipt.TxHash)
	return nil
}
