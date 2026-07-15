package saas

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestDeployerOperationPollingIAMIsLeastPrivilege(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile("iam.tf")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	operationRole := terraformResourceBlock(t, source,
		"google_project_iam_custom_role", "cloud_run_operation_viewer")
	permissionList := regexp.MustCompile(`(?s)permissions\s*=\s*\[(.*?)\]`).FindStringSubmatch(operationRole)
	if len(permissionList) != 2 {
		t.Fatalf("operation polling role has no permission list:\n%s", operationRole)
	}
	permissions := regexp.MustCompile(`"([a-z.]+)"`).FindAllStringSubmatch(
		permissionList[1], -1)
	if len(permissions) != 1 || permissions[0][1] != "run.operations.get" {
		t.Fatalf("Cloud Run operation permissions = %#v, want only run.operations.get", permissions)
	}
	binding := terraformResourceBlock(t, source,
		"google_project_iam_member", "deployer_cloud_run_operations")
	for _, want := range []string{
		`project\s*=\s*var\.project_id`,
		`role\s*=\s*google_project_iam_custom_role\.cloud_run_operation_viewer\.id`,
		`member\s*=\s*"serviceAccount:\$\{google_service_account\.deployer\.email\}"`,
	} {
		if !regexp.MustCompile(want).MatchString(binding) {
			t.Fatalf("operation polling binding missing %q:\n%s", want, binding)
		}
	}
	if references := strings.Count(source,
		"google_project_iam_custom_role.cloud_run_operation_viewer.id"); references != 1 {
		t.Fatalf("operation polling role binding references = %d, want exactly 1", references)
	}
	projectMember := regexp.MustCompile(`(?ms)^resource "google_project_iam_member" "[^"]+" \{\n(.*?^\})`)
	for _, block := range projectMember.FindAllString(source, -1) {
		if regexp.MustCompile(`role\s*=\s*"roles/(run\.admin|artifactregistry\.writer)"`).MatchString(block) {
			t.Fatalf("broad deployer role returned:\n%s", block)
		}
	}
	for _, scoped := range []struct {
		resourceType string
		name         string
		role         string
	}{
		{"google_artifact_registry_repository_iam_member", "deployer_images", "roles/artifactregistry.writer"},
		{"google_cloud_run_v2_service_iam_member", "deployer_serve", "roles/run.admin"},
		{"google_cloud_run_v2_job_iam_member", "deployer_scan", "roles/run.admin"},
		{"google_cloud_run_v2_job_iam_member", "deployer_delivery", "roles/run.admin"},
	} {
		block := terraformResourceBlock(t, source, scoped.resourceType, scoped.name)
		if !regexp.MustCompile(`role\s*=\s*"` + regexp.QuoteMeta(scoped.role) + `"`).MatchString(block) {
			t.Errorf("%s.%s does not grant %s", scoped.resourceType, scoped.name, scoped.role)
		}
	}
	if !strings.Contains(source, `assertion.sub == 'repo:${var.git_repo}:environment:saas'`) {
		t.Error("exact saas-environment WIF subject is missing")
	}
}

func terraformResourceBlock(t *testing.T, source, resourceType, name string) string {
	t.Helper()
	pattern := `(?ms)^resource "` + regexp.QuoteMeta(resourceType) + `" "` + regexp.QuoteMeta(name) + `" \{\n(.*?^\})`
	block := regexp.MustCompile(pattern).FindString(source)
	if block == "" {
		t.Fatalf("missing Terraform resource %s.%s", resourceType, name)
	}
	return block
}
