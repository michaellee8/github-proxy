package broker

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

const (
	maxGraphQLBodyBytes = 1 << 20
	maxGraphQLTokens    = 4096
)

type graphQLOperationFamily struct {
	operation     ast.Operation
	ownerVariable string
	nameVariable  string
	schemaType    string
}

var graphQLOperationFamilies = map[string]graphQLOperationFamily{
	"IssueByNumber":           repositoryQueryFamily("repo"),
	"IssueList":               repositoryQueryFamily("repo"),
	"IssueNodeID":             repositoryQueryFamily("name"),
	"IssueRepositoryInfo":     repositoryQueryFamily("name"),
	"IssueTemplates":          repositoryQueryFamily("name"),
	"LabelList":               repositoryQueryFamily("repo"),
	"PullRequestByNumber":     repositoryQueryFamily("repo"),
	"PullRequestForBranch":    repositoryQueryFamily("repo"),
	"PullRequestList":         repositoryQueryFamily("repo"),
	"PullRequestTemplates":    repositoryQueryFamily("name"),
	"RepositoryInfo":          repositoryQueryFamily("name"),
	"RepositoryIssueTypes":    repositoryQueryFamily("name"),
	"RepositoryLabelList":     repositoryQueryFamily("name"),
	"RepositoryMilestoneList": repositoryQueryFamily("name"),
	"RepositoryReleaseList":   repositoryQueryFamily("name"),
	"Release_fields":          schemaQueryFamily("Release"),
}

func repositoryQueryFamily(nameVariable string) graphQLOperationFamily {
	return graphQLOperationFamily{operation: ast.Query, ownerVariable: "owner", nameVariable: nameVariable}
}

func schemaQueryFamily(schemaType string) graphQLOperationFamily {
	return graphQLOperationFamily{operation: ast.Query, schemaType: schemaType}
}

type graphQLRequest struct {
	Query         string         `json:"query"`
	Variables     map[string]any `json:"variables,omitempty"`
	OperationName string         `json:"operationName,omitempty"`
}

// graphQLRepositoryFields is deliberately conservative. A newly used gh field
// fails closed until it is reviewed for graph traversal outside the capability.
var graphQLRepositoryFields = map[string]bool{
	"__typename":       true,
	"activeLockReason": true, "additions": true, "assignees": true, "author": true, "authoredDate": true, "authors": true, "avatarUrl": true,
	"baseRefName": true, "baseRefOid": true, "body": true, "bodyHTML": true, "bodyText": true,
	"changedFiles": true, "closedAt": true, "color": true, "comments": true, "commit": true, "committedDate": true, "commits": true, "completedAt": true, "conclusion": true, "contexts": true, "createdAt": true,
	"defaultBranchRef": true, "deleteBranchOnMerge": true, "deletions": true, "description": true, "descriptionHTML": true, "detailsUrl": true, "dueOn": true,
	"edges": true, "endCursor": true,
	"fileCount": true, "filename": true, "files": true,
	"hasDiscussionsEnabled": true, "hasIssuesEnabled": true, "hasNextPage": true, "hasPreviousPage": true, "hasProjectsEnabled": true, "hasWikiEnabled": true, "headRefName": true, "headRefOid": true, "homepageUrl": true,
	"id": true, "immutable": true, "isArchived": true, "isBot": true, "isDisabled": true, "isDraft": true, "isEmpty": true, "isFork": true, "isLatest": true, "isPrerelease": true, "isPrivate": true, "issue": true, "issueOrPullRequest": true, "issues": true, "issueTemplates": true, "issueTypes": true,
	"label": true, "labels": true, "language": true, "languages": true, "licenseInfo": true, "locked": true, "login": true,
	"maintainerCanModify": true, "mergeable": true, "mergeCommit": true, "mergeCommitAllowed": true, "mergedAt": true, "mergeStateStatus": true, "message": true, "messageBody": true, "messageHeadline": true, "milestone": true, "milestones": true,
	"name": true, "nameWithOwner": true, "nodes": true, "number": true,
	"object": true, "oid": true, "owner": true,
	"pageInfo": true, "potentialMergeCommit": true, "primaryLanguage": true, "progressPercentage": true, "publishedAt": true, "pullRequest": true, "pullRequests": true, "pullRequestTemplates": true, "pushedAt": true,
	"rebaseMergeAllowed": true, "refs": true, "release": true, "releases": true, "requestedReviewer": true, "reviewDecision": true, "reviewRequests": true, "reviews": true,
	"size": true, "squashMergeAllowed": true, "sshUrl": true, "startCursor": true, "startedAt": true, "state": true, "stateReason": true, "status": true, "statusCheckRollup": true,
	"tag": true, "tagName": true, "target": true, "text": true, "title": true, "totalCount": true,
	"updatedAt": true, "url": true,
	"viewerCanAdminister": true, "viewerCanCreateProjects": true, "viewerCanSubscribe": true, "viewerPermission": true, "viewerSubscription": true, "visibility": true,
	"workflowName": true,
}

// Identity-bearing fields leave repository provenance and enter a deliberately
// shallow projection. This prevents an issue's author, owner, or assignee from
// becoming a path back into that identity's global graph.
var graphQLIdentityBoundaries = map[string]bool{
	"assignees": true, "author": true, "authors": true, "owner": true,
	"requestedReviewer": true, "reviewRequests": true,
}

var graphQLIdentityFields = map[string]bool{
	"__typename": true, "avatarUrl": true,
	"edges": true, "endCursor": true,
	"hasNextPage": true, "hasPreviousPage": true,
	"id": true, "isBot": true, "isDisabled": true,
	"login": true,
	"name":  true, "nodes": true,
	"pageInfo":          true,
	"requestedReviewer": true,
	"startCursor":       true,
	"totalCount":        true,
	"url":               true,
}

func (h *handler) serveGraphQL(w http.ResponseWriter, req *http.Request, session Session) {
	if req.Method != http.MethodPost {
		writeJSON(w, http.StatusForbidden, errorResponse{Message: "operation is not allowed by this capability", Code: "PGH_POLICY_DENIED"})
		return
	}

	payload, status, response := authorizeGraphQL(req.Body, session)
	if response.Code != "" {
		writeJSON(w, status, response)
		return
	}

	endpoint, err := graphQLEndpoint(session.Repository.APIBaseURL)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Message: "upstream host is misconfigured", Code: "PGH_UPSTREAM_INVALID"})
		return
	}
	body, err := json.Marshal(payload)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errorResponse{Message: "failed to build upstream request", Code: "PGH_UPSTREAM_ERROR"})
		return
	}
	upstream, err := http.NewRequestWithContext(req.Context(), http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errorResponse{Message: "failed to build upstream request", Code: "PGH_UPSTREAM_ERROR"})
		return
	}
	copyEndToEndHeaders(upstream.Header, req.Header)
	upstream.Header.Set("Authorization", "Bearer "+session.Repository.UpstreamToken)
	upstream.Header.Set("Content-Type", "application/json")

	responseFromGitHub, err := h.transport.RoundTrip(upstream)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errorResponse{Message: "GitHub request failed", Code: "PGH_UPSTREAM_ERROR"})
		return
	}
	defer responseFromGitHub.Body.Close()
	copyEndToEndHeaders(w.Header(), responseFromGitHub.Header)
	w.WriteHeader(responseFromGitHub.StatusCode)
	_, _ = io.Copy(w, responseFromGitHub.Body)
}

func authorizeGraphQL(body io.Reader, session Session) (graphQLRequest, int, errorResponse) {
	var payload graphQLRequest
	decoder := json.NewDecoder(io.LimitReader(body, maxGraphQLBodyBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, http.StatusBadRequest, invalidGraphQLResponse()
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return payload, http.StatusBadRequest, invalidGraphQLResponse()
	}

	document, err := parser.ParseQueryWithTokenLimit(&ast.Source{Name: "capability-request", Input: payload.Query}, maxGraphQLTokens)
	if err != nil || len(document.Operations) != 1 {
		return payload, http.StatusBadRequest, invalidGraphQLResponse()
	}
	operation := document.Operations[0]
	if operation.Name == "" || (payload.OperationName != "" && payload.OperationName != operation.Name) {
		return payload, http.StatusBadRequest, invalidGraphQLResponse()
	}
	family, ok := graphQLOperationFamilies[operation.Name]
	if !ok {
		return payload, http.StatusForbidden, errorResponse{Message: "operation is not registered", Code: "PGH_OPERATION_UNKNOWN"}
	}
	if family.schemaType != "" && len(payload.Variables) != 0 {
		return payload, http.StatusForbidden, errorResponse{Message: "operation is not allowed by this capability", Code: "PGH_POLICY_DENIED"}
	}
	if !validGraphQLOperation(document, operation, family) {
		return payload, http.StatusForbidden, errorResponse{Message: "operation is not allowed by this capability", Code: "PGH_POLICY_DENIED"}
	}
	if family.schemaType != "" {
		return payload, 0, errorResponse{}
	}

	variables := make(map[string]any, len(payload.Variables)+2)
	for name, value := range payload.Variables {
		variables[name] = value
	}
	variables[family.ownerVariable] = session.Repository.Owner
	variables[family.nameVariable] = session.Repository.Name
	payload.Variables = variables
	return payload, 0, errorResponse{}
}

func validGraphQLOperation(document *ast.QueryDocument, operation *ast.OperationDefinition, family graphQLOperationFamily) bool {
	if operation.Operation != family.operation || family.operation != ast.Query {
		return false
	}
	if family.schemaType != "" {
		return validGraphQLSchemaProbe(operation, family.schemaType)
	}
	if operation.VariableDefinitions.ForName(family.ownerVariable) == nil || operation.VariableDefinitions.ForName(family.nameVariable) == nil {
		return false
	}
	if len(operation.SelectionSet) == 0 {
		return false
	}
	for _, selection := range operation.SelectionSet {
		field, ok := selection.(*ast.Field)
		if !ok || field.Name != "repository" {
			return false
		}
		owner := field.Arguments.ForName("owner")
		name := field.Arguments.ForName("name")
		if !graphQLVariable(owner, family.ownerVariable) || !graphQLVariable(name, family.nameVariable) {
			return false
		}
		if !validGraphQLSelections(document, field.SelectionSet, false, make(map[string]bool)) {
			return false
		}
	}
	return true
}

func validGraphQLSchemaProbe(operation *ast.OperationDefinition, schemaType string) bool {
	if len(operation.VariableDefinitions) != 0 || len(operation.Directives) != 0 || len(operation.SelectionSet) != 1 {
		return false
	}
	root, ok := operation.SelectionSet[0].(*ast.Field)
	if !ok || root.Name != "__type" || root.Alias != schemaType || len(root.Arguments) != 1 ||
		len(root.Directives) != 0 || len(root.SelectionSet) != 1 {
		return false
	}
	typeName := root.Arguments.ForName("name")
	if typeName == nil || typeName.Value == nil || typeName.Value.Kind != ast.StringValue || typeName.Value.Raw != schemaType {
		return false
	}
	fields, ok := root.SelectionSet[0].(*ast.Field)
	if !ok || fields.Name != "fields" || fields.Alias != fields.Name || len(fields.Arguments) != 0 ||
		len(fields.Directives) != 0 || len(fields.SelectionSet) != 1 {
		return false
	}
	name, ok := fields.SelectionSet[0].(*ast.Field)
	return ok && name.Name == "name" && name.Alias == name.Name && len(name.Arguments) == 0 &&
		len(name.Directives) == 0 && len(name.SelectionSet) == 0
}

func graphQLVariable(argument *ast.Argument, expected string) bool {
	return argument != nil && argument.Value != nil && argument.Value.Kind == ast.Variable && argument.Value.Raw == expected
}

func validGraphQLSelections(document *ast.QueryDocument, selections ast.SelectionSet, identityScope bool, visiting map[string]bool) bool {
	for _, selection := range selections {
		switch value := selection.(type) {
		case *ast.Field:
			if !graphQLRepositoryFields[value.Name] {
				return false
			}
			if identityScope && !graphQLIdentityFields[value.Name] {
				return false
			}
			nextIdentityScope := identityScope || graphQLIdentityBoundaries[value.Name]
			if !validGraphQLSelections(document, value.SelectionSet, nextIdentityScope, visiting) {
				return false
			}
		case *ast.InlineFragment:
			if !validGraphQLSelections(document, value.SelectionSet, identityScope, visiting) {
				return false
			}
		case *ast.FragmentSpread:
			fragment := document.Fragments.ForName(value.Name)
			if fragment == nil {
				return false
			}
			key := fragment.Name
			if identityScope {
				key += ":identity"
			}
			if visiting[key] {
				return false
			}
			visiting[key] = true
			valid := validGraphQLSelections(document, fragment.SelectionSet, identityScope, visiting)
			delete(visiting, key)
			if !valid {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func graphQLEndpoint(apiBaseURL string) (*url.URL, error) {
	endpoint, err := url.Parse(apiBaseURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil {
		return nil, errors.New("invalid API base URL")
	}
	endpoint.RawQuery = ""
	endpoint.Fragment = ""
	if strings.HasSuffix(strings.TrimSuffix(endpoint.Path, "/"), "/api/v3") {
		endpoint.Path = strings.TrimSuffix(strings.TrimSuffix(endpoint.Path, "/"), "/api/v3") + "/api/graphql"
	} else {
		endpoint.Path = strings.TrimSuffix(endpoint.Path, "/") + "/graphql"
	}
	return endpoint, nil
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func invalidGraphQLResponse() errorResponse {
	return errorResponse{Message: "GraphQL request is invalid", Code: "PGH_GRAPHQL_INVALID"}
}
