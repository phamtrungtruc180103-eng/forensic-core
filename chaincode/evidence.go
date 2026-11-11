package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type EvidenceContract struct{ contractapi.Contract }

type Evidence struct {
	EvidenceID         string `json:"evidenceID"`
	CaseID             string `json:"caseID"`
	FileName           string `json:"fileName"`
	SHA256Hash         string `json:"sha256Hash"`
	MerkleRoot         string `json:"merkleRoot"`
	Investigator       string `json:"investigator"`
	Timestamp          string `json:"timestamp"`
	Action             string `json:"action"`
	EvidenceType       string `json:"evidenceType"`
	Source             string `json:"source"`
	AcquisitionMethod  string `json:"acquisitionMethod"`
	CollectedAt        string `json:"collectedAt"`
	FromHolder         string `json:"fromHolder"`
	ToHolder           string `json:"toHolder"`
	CurrentHolder      string `json:"currentHolder"`
	Reason             string `json:"reason"`
	Result             string `json:"result"`
	VerificationStatus string `json:"verificationStatus"`
	ReferenceHash      string `json:"referenceHash"`
	CurrentHash        string `json:"currentHash"`
	VerifiedAt         string `json:"verifiedAt"`
	Verifier           string `json:"verifier"`
	SignerID           string `json:"signerID"`
	SignerMSP          string `json:"signerMSP"`
	LastTxID           string `json:"lastTxID"`
	Status             string `json:"status"`
}

type CustodyEvent struct {
	TxID               string `json:"txID"`
	EvidenceID         string `json:"evidenceID"`
	Action             string `json:"action"`
	ActorID            string `json:"actorID"`
	FromHolder         string `json:"fromHolder"`
	ToHolder           string `json:"toHolder"`
	Timestamp          string `json:"timestamp"`
	Reason             string `json:"reason"`
	Result             string `json:"result"`
	SHA256Hash         string `json:"sha256Hash"`
	MerkleRoot         string `json:"merkleRoot"`
	VerificationStatus string `json:"verificationStatus"`
	ReferenceHash      string `json:"referenceHash"`
	CurrentHash        string `json:"currentHash"`
	SignerID           string `json:"signerID"`
	SignerMSP          string `json:"signerMSP"`
	IsDelete           bool   `json:"isDelete"`
}

type Staff struct {
	StaffID        string `json:"staffID"`
	EnrollmentID   string `json:"enrollmentID"`
	Organization   string `json:"organization"`
	Role           string `json:"role"`
	Status         string `json:"status"`
	IdentityStatus string `json:"identityStatus"`
	CreatedAt      string `json:"createdAt"`
	CreatedBy      string `json:"createdBy"`
	UpdatedAt      string `json:"updatedAt"`
	UpdatedBy      string `json:"updatedBy"`
	LastTxID       string `json:"lastTxID"`
}

func transactionTime(ctx contractapi.TransactionContextInterface) string {
	timestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return time.Now().UTC().Format(time.RFC3339Nano)
	}
	return time.Unix(timestamp.Seconds, int64(timestamp.Nanos)).UTC().Format(time.RFC3339Nano)
}

func identity(ctx contractapi.TransactionContextInterface) (string, string, bool, error) {
	mspID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", "", false, fmt.Errorf("read invoker MSP: %w", err)
	}
	certificate, err := ctx.GetClientIdentity().GetX509Certificate()
	if err != nil {
		return "", "", false, fmt.Errorf("read invoker certificate: %w", err)
	}
	isAdmin := false
	for _, unit := range certificate.Subject.OrganizationalUnit {
		if strings.EqualFold(unit, "admin") {
			isAdmin = true
			break
		}
	}
	return certificate.Subject.CommonName, mspID, isAdmin, nil
}

func requireAdmin(ctx contractapi.TransactionContextInterface) (string, string, error) {
	signerID, signerMSP, isAdmin, err := identity(ctx)
	if err != nil {
		return "", "", err
	}
	if !isAdmin {
		return "", "", fmt.Errorf("Fabric admin identity is required")
	}
	return signerID, signerMSP, nil
}

func roleAllowed(role string, roles ...string) bool {
	for _, allowed := range roles {
		if role == allowed {
			return true
		}
	}
	return false
}

func (c *EvidenceContract) authorizeStaff(ctx contractapi.TransactionContextInterface, actorID string, roles ...string) (string, string, error) {
	signerID, signerMSP, isAdmin, err := identity(ctx)
	if err != nil {
		return "", "", err
	}
	staff, err := c.QueryStaff(ctx, actorID)
	if err != nil {
		return "", "", err
	}
	if staff.Status != "ACTIVE" || staff.IdentityStatus != "ACTIVE" {
		return "", "", fmt.Errorf("staff identity is not active: %s", actorID)
	}
	if !roleAllowed(staff.Role, roles...) {
		return "", "", fmt.Errorf("staff role %s is not allowed for this operation", staff.Role)
	}
	if isAdmin {
		return signerID, signerMSP, nil
	}
	if staff.EnrollmentID != signerID || staff.Organization != signerMSP {
		return "", "", fmt.Errorf("authenticated Fabric identity does not match actor %s", actorID)
	}
	if attributeStaffID, found, attributeErr := ctx.GetClientIdentity().GetAttributeValue("staffID"); attributeErr != nil {
		return "", "", fmt.Errorf("read staffID certificate attribute: %w", attributeErr)
	} else if found && attributeStaffID != actorID {
		return "", "", fmt.Errorf("staffID certificate attribute does not match actor %s", actorID)
	}
	return signerID, signerMSP, nil
}

func validStaffRole(role string) bool {
	return roleAllowed(role, "INVESTIGATOR", "ANALYST", "SUPERVISOR", "OBSERVER")
}

func (c *EvidenceContract) RegisterStaff(ctx contractapi.TransactionContextInterface, staffID, enrollmentID, organization, role, createdAt, createdBy string) error {
	signerID, _, err := requireAdmin(ctx)
	if err != nil {
		return err
	}
	if strings.TrimSpace(staffID) == "" || strings.TrimSpace(enrollmentID) == "" || strings.TrimSpace(organization) == "" || strings.TrimSpace(createdBy) == "" {
		return fmt.Errorf("staff ID, enrollment ID, organization and created by are required")
	}
	if !validStaffRole(role) {
		return fmt.Errorf("invalid staff role: %s", role)
	}
	if existing, _ := ctx.GetStub().GetState(staffID); existing != nil {
		return fmt.Errorf("staff already exists: %s", staffID)
	}
	staff := Staff{
		StaffID: staffID, EnrollmentID: enrollmentID, Organization: organization, Role: role,
		Status: "ACTIVE", IdentityStatus: "ACTIVE", CreatedAt: createdAt, CreatedBy: createdBy,
		UpdatedAt: transactionTime(ctx), UpdatedBy: signerID, LastTxID: ctx.GetStub().GetTxID(),
	}
	bytes, err := json.Marshal(staff)
	if err != nil {
		return fmt.Errorf("serialize staff: %w", err)
	}
	return ctx.GetStub().PutState(staffID, bytes)
}

func (c *EvidenceContract) UpdateStaffRole(ctx contractapi.TransactionContextInterface, staffID, role, updatedBy string) error {
	signerID, _, err := requireAdmin(ctx)
	if err != nil {
		return err
	}
	staff, err := c.QueryStaff(ctx, staffID)
	if err != nil {
		return err
	}
	if !validStaffRole(role) {
		return fmt.Errorf("invalid staff role: %s", role)
	}
	staff.Role, staff.UpdatedBy, staff.UpdatedAt = role, updatedBy, transactionTime(ctx)
	if staff.UpdatedBy == "" {
		staff.UpdatedBy = signerID
	}
	staff.LastTxID = ctx.GetStub().GetTxID()
	bytes, err := json.Marshal(staff)
	if err != nil {
		return fmt.Errorf("serialize staff role update: %w", err)
	}
	return ctx.GetStub().PutState(staffID, bytes)
}

func (c *EvidenceContract) DeactivateStaff(ctx contractapi.TransactionContextInterface, staffID, updatedBy string) error {
	signerID, _, err := requireAdmin(ctx)
	if err != nil {
		return err
	}
	staff, err := c.QueryStaff(ctx, staffID)
	if err != nil {
		return err
	}
	staff.Status, staff.IdentityStatus = "INACTIVE", "REVOKED"
	staff.UpdatedBy, staff.UpdatedAt, staff.LastTxID = updatedBy, transactionTime(ctx), ctx.GetStub().GetTxID()
	if staff.UpdatedBy == "" {
		staff.UpdatedBy = signerID
	}
	bytes, err := json.Marshal(staff)
	if err != nil {
		return fmt.Errorf("serialize staff deactivation: %w", err)
	}
	return ctx.GetStub().PutState(staffID, bytes)
}

func (c *EvidenceContract) QueryStaff(ctx contractapi.TransactionContextInterface, staffID string) (*Staff, error) {
	bytes, err := ctx.GetStub().GetState(staffID)
	if err != nil {
		return nil, fmt.Errorf("get staff %s: %w", staffID, err)
	}
	if bytes == nil {
		return nil, fmt.Errorf("staff not found: %s", staffID)
	}
	var staff Staff
	if err := json.Unmarshal(bytes, &staff); err != nil {
		return nil, fmt.Errorf("decode staff %s: %w", staffID, err)
	}
	if staff.StaffID != staffID {
		return nil, fmt.Errorf("ledger key %s is not a staff record", staffID)
	}
	if staff.IdentityStatus == "" {
		staff.IdentityStatus = staff.Status
	}
	return &staff, nil
}

func (c *EvidenceContract) RecordEvidence(ctx contractapi.TransactionContextInterface, id, caseID, fileName, hash, merkleRoot, investigator, timestamp, evidenceType, source, acquisitionMethod, collectedAt string) error {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(caseID) == "" || strings.TrimSpace(hash) == "" {
		return fmt.Errorf("evidence ID, case ID and hash are required")
	}
	if existing, _ := ctx.GetStub().GetState(id); existing != nil {
		return fmt.Errorf("evidence already exists: %s", id)
	}
	signerID, signerMSP, err := c.authorizeStaff(ctx, investigator, "INVESTIGATOR", "ANALYST", "SUPERVISOR")
	if err != nil {
		return err
	}
	existing, err := c.QueryAllEvidence(ctx)
	if err != nil {
		return err
	}
	for _, item := range existing {
		if item.Status != "DELETED" && strings.EqualFold(item.SHA256Hash, hash) {
			return fmt.Errorf("SHA-256 already belongs to evidence: %s", item.EvidenceID)
		}
	}
	_ = timestamp
	if collectedAt == "" {
		collectedAt = transactionTime(ctx)
	}
	evidence := Evidence{
		EvidenceID: id, CaseID: caseID, FileName: fileName, SHA256Hash: hash, MerkleRoot: merkleRoot,
		Investigator: investigator, Timestamp: transactionTime(ctx), Action: "COLLECT",
		EvidenceType: evidenceType, Source: source, AcquisitionMethod: acquisitionMethod, CollectedAt: collectedAt,
		CurrentHolder: investigator, VerificationStatus: "NOT_VERIFIED", SignerID: signerID, SignerMSP: signerMSP,
		LastTxID: ctx.GetStub().GetTxID(), Status: "ACTIVE",
	}
	bytes, err := json.Marshal(evidence)
	if err != nil {
		return fmt.Errorf("serialize evidence: %w", err)
	}
	return ctx.GetStub().PutState(id, bytes)
}

func (c *EvidenceContract) RecordCustodyEvent(ctx contractapi.TransactionContextInterface, id, action, actorID, fromHolder, toHolder, reason, result, referenceHash, currentHash, timestamp string) (*Evidence, error) {
	evidence, err := c.QueryEvidence(ctx, id)
	if err != nil {
		return nil, err
	}
	if evidence.Status == "DELETED" {
		return nil, fmt.Errorf("evidence is deleted: %s", id)
	}
	if strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("custody event reason is required")
	}
	var roles []string
	switch action {
	case "ACCESS":
		roles = []string{"INVESTIGATOR", "ANALYST", "SUPERVISOR", "OBSERVER"}
	case "TRANSFER", "RECEIVE":
		roles = []string{"INVESTIGATOR", "SUPERVISOR"}
	case "ANALYZE", "VERIFY":
		roles = []string{"INVESTIGATOR", "ANALYST", "SUPERVISOR"}
	default:
		return nil, fmt.Errorf("unsupported custody action: %s", action)
	}
	signerID, signerMSP, err := c.authorizeStaff(ctx, actorID, roles...)
	if err != nil {
		return nil, err
	}
	if action == "TRANSFER" && (strings.TrimSpace(fromHolder) == "" || strings.TrimSpace(toHolder) == "") {
		return nil, fmt.Errorf("transfer requires fromHolder and toHolder")
	}
	if action == "TRANSFER" && evidence.CurrentHolder != "" && evidence.CurrentHolder != fromHolder {
		return nil, fmt.Errorf("fromHolder %s does not match current holder %s", fromHolder, evidence.CurrentHolder)
	}
	if action == "RECEIVE" && strings.TrimSpace(toHolder) == "" {
		return nil, fmt.Errorf("receive requires toHolder")
	}
	if action == "RECEIVE" && evidence.ToHolder != "" && evidence.ToHolder != actorID {
		return nil, fmt.Errorf("only pending recipient %s may receive evidence", evidence.ToHolder)
	}
	if action == "VERIFY" && !roleAllowed(result, "MATCH", "MISMATCH", "NOT_VERIFIED") {
		return nil, fmt.Errorf("invalid verification result: %s", result)
	}
	_ = timestamp
	evidence.Action, evidence.Investigator, evidence.Timestamp = action, actorID, transactionTime(ctx)
	evidence.FromHolder, evidence.ToHolder, evidence.Reason, evidence.Result = fromHolder, toHolder, reason, result
	evidence.SignerID, evidence.SignerMSP, evidence.LastTxID = signerID, signerMSP, ctx.GetStub().GetTxID()
	if toHolder != "" && action != "TRANSFER" {
		evidence.CurrentHolder = toHolder
	}
	if action == "VERIFY" {
		evidence.VerificationStatus, evidence.ReferenceHash, evidence.CurrentHash = result, referenceHash, currentHash
		evidence.VerifiedAt, evidence.Verifier = evidence.Timestamp, actorID
	}
	bytes, err := json.Marshal(evidence)
	if err != nil {
		return nil, fmt.Errorf("serialize custody event: %w", err)
	}
	if err := ctx.GetStub().PutState(id, bytes); err != nil {
		return nil, err
	}
	return evidence, nil
}

func (c *EvidenceContract) AccessEvidence(ctx contractapi.TransactionContextInterface, id, actorID, timestamp string) (*Evidence, error) {
	return c.RecordCustodyEvent(ctx, id, "ACCESS", actorID, "", "", "Legacy access event", "", "", "", timestamp)
}

func (c *EvidenceContract) TransferCustody(ctx contractapi.TransactionContextInterface, id, fromHolder, toHolder, actorID, timestamp string) (*Evidence, error) {
	return c.RecordCustodyEvent(ctx, id, "TRANSFER", actorID, fromHolder, toHolder, "Legacy transfer event", "", "", "", timestamp)
}

func (c *EvidenceContract) RecordCourtAction(ctx contractapi.TransactionContextInterface, id, action, actorID, courtID, note, timestamp string) (*Evidence, error) {
	if !roleAllowed(action, "COURT_REVIEW", "ADMIT", "REJECT", "COURT_ORDER") {
		return nil, fmt.Errorf("invalid court action: %s", action)
	}
	return c.RecordCustodyEvent(ctx, id, "ANALYZE", actorID, "", "", note, action+":"+courtID, "", "", timestamp)
}

func (c *EvidenceContract) QueryEvidence(ctx contractapi.TransactionContextInterface, id string) (*Evidence, error) {
	bytes, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("get evidence %s: %w", id, err)
	}
	if bytes == nil {
		return nil, fmt.Errorf("evidence not found: %s", id)
	}
	var evidence Evidence
	if err := json.Unmarshal(bytes, &evidence); err != nil {
		return nil, fmt.Errorf("decode evidence %s: %w", id, err)
	}
	if evidence.EvidenceID != id {
		return nil, fmt.Errorf("ledger key %s is not an evidence record", id)
	}
	return &evidence, nil
}

func (c *EvidenceContract) DeleteEvidence(ctx contractapi.TransactionContextInterface, id string) error {
	signerID, signerMSP, err := requireAdmin(ctx)
	if err != nil {
		return err
	}
	evidence, err := c.QueryEvidence(ctx, id)
	if err != nil {
		return err
	}
	evidence.Action, evidence.Status, evidence.Timestamp = "DELETE", "DELETED", transactionTime(ctx)
	evidence.SignerID, evidence.SignerMSP, evidence.LastTxID = signerID, signerMSP, ctx.GetStub().GetTxID()
	bytes, err := json.Marshal(evidence)
	if err != nil {
		return fmt.Errorf("serialize evidence deletion: %w", err)
	}
	return ctx.GetStub().PutState(id, bytes)
}

func (c *EvidenceContract) QueryEvidenceByCase(ctx contractapi.TransactionContextInterface, caseID string) ([]*Evidence, error) {
	if strings.TrimSpace(caseID) == "" {
		return nil, fmt.Errorf("case ID is required")
	}
	query := fmt.Sprintf(`{"selector":{"caseID":%q,"evidenceID":{"$exists":true}}}`, caseID)
	return c.queryEvidenceSelector(ctx, query)
}

func (c *EvidenceContract) QueryAllEvidence(ctx contractapi.TransactionContextInterface) ([]*Evidence, error) {
	return c.queryEvidenceSelector(ctx, `{"selector":{"evidenceID":{"$exists":true}}}`)
}

func (c *EvidenceContract) queryEvidenceSelector(ctx contractapi.TransactionContextInterface, query string) ([]*Evidence, error) {
	iterator, err := ctx.GetStub().GetQueryResult(query)
	if err != nil {
		return nil, fmt.Errorf("rich query evidence: %w", err)
	}
	defer iterator.Close()
	results := make([]*Evidence, 0)
	for iterator.HasNext() {
		item, err := iterator.Next()
		if err != nil {
			return nil, err
		}
		var evidence Evidence
		if err := json.Unmarshal(item.Value, &evidence); err != nil {
			return nil, fmt.Errorf("decode rich query result %s: %w", item.Key, err)
		}
		if evidence.EvidenceID != "" {
			results = append(results, &evidence)
		}
	}
	return results, nil
}

func (c *EvidenceContract) QueryHistory(ctx contractapi.TransactionContextInterface, id string) ([]*CustodyEvent, error) {
	iterator, err := ctx.GetStub().GetHistoryForKey(id)
	if err != nil {
		return nil, fmt.Errorf("query history: %w", err)
	}
	defer iterator.Close()
	history := make([]*CustodyEvent, 0)
	for iterator.HasNext() {
		item, err := iterator.Next()
		if err != nil {
			return nil, err
		}
		event := &CustodyEvent{TxID: item.TxId, EvidenceID: id, IsDelete: item.IsDelete}
		if !item.IsDelete {
			var evidence Evidence
			if err := json.Unmarshal(item.Value, &evidence); err != nil {
				return nil, fmt.Errorf("decode history %s: %w", item.TxId, err)
			}
			event.Action, event.ActorID, event.Timestamp = evidence.Action, evidence.Investigator, evidence.Timestamp
			event.FromHolder, event.ToHolder = evidence.FromHolder, evidence.ToHolder
			event.Reason, event.Result = evidence.Reason, evidence.Result
			event.SHA256Hash, event.MerkleRoot = evidence.SHA256Hash, evidence.MerkleRoot
			event.VerificationStatus, event.ReferenceHash, event.CurrentHash = evidence.VerificationStatus, evidence.ReferenceHash, evidence.CurrentHash
			event.SignerID, event.SignerMSP = evidence.SignerID, evidence.SignerMSP
		}
		history = append(history, event)
	}
	return history, nil
}

func main() {
	cc, err := contractapi.NewChaincode(&EvidenceContract{})
	if err != nil {
		panic(err.Error())
	}
	if err := cc.Start(); err != nil {
		panic(err.Error())
	}
}
