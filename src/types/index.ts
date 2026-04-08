// ==================== FINDING TYPES ====================

export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type FindingStatus = 'open' | 'in_progress' | 'remediated' | 'suppressed';
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed';
export type RemediationStatus = 'generated' | 'pr_opened' | 'merged' | 'failed';
export type PRStatus = 'pending' | 'opened' | 'merged' | 'closed';

export interface PolicyRule {
  id: string;
  service: string;
  severity: Severity;
  title: string;
  description: string;
  recommendation: string;
  frameworkMappings: string[]; // e.g., ["SOC2-CC6.1", "ISO27001-A.8.24"]
  check: (resource: ScannedResource) => PolicyCheckResult;
}

export interface PolicyCheckResult {
  passed: boolean;
  evidence: Record<string, unknown>;
  details?: string;
}

export interface ScannedResource {
  arn: string;
  resourceType: string;
  service: string;
  region: string;
  name: string;
  configuration: Record<string, unknown>;
  tags?: Record<string, string>;
}

export interface ScanFinding {
  ruleId: string;
  resource: ScannedResource;
  severity: Severity;
  title: string;
  description: string;
  evidence: Record<string, unknown>;
  recommendation: string;
  frameworkMappings: string[];
}

// ==================== COMPLIANCE TYPES ====================

export interface FrameworkDefinition {
  key: string;
  name: string;
  version: string;
  description: string;
  controls: ControlDefinition[];
}

export interface ControlDefinition {
  controlCode: string;
  title: string;
  description: string;
  category: string;
  severity: Severity;
}

export interface CompliancePosture {
  frameworkKey: string;
  frameworkName: string;
  totalControls: number;
  passingControls: number;
  failingControls: number;
  score: number; // 0-100
  controlStatuses: ControlStatus[];
}

export interface ControlStatus {
  controlCode: string;
  title: string;
  status: 'passing' | 'failing' | 'not_evaluated';
  findingsCount: number;
}

// ==================== REMEDIATION TYPES ====================

export type IaCFormat = 'terraform' | 'cloudformation' | 'aws_cli' | 'aws_cdk';

export interface RemediationRequest {
  findingId: string;
  ruleId: string;
  service: string;
  severity: Severity;
  title: string;
  description: string;
  resourceArn: string;
  resourceType: string;
  currentConfig: Record<string, unknown>;
  recommendation: string;
  frameworkControls: string[];
  preferredIac: IaCFormat;
}

export interface RemediationResult {
  code: string;
  format: IaCFormat;
  explanation: string;
  riskLevel: 'low' | 'medium' | 'high';
  blastRadius: string;
  reasoning: string;
}

// ==================== AWS TYPES ====================

export interface AWSCredentials {
  accessKeyId?: string;
  secretAccessKey?: string;
  roleArn?: string;
  externalId?: string;
  region: string;
}

export interface ScanProgress {
  status: ScanStatus;
  currentService: string;
  servicesCompleted: number;
  totalServices: number;
  resourcesFound: number;
  findingsCount: number;
  message: string;
}

// ==================== API TYPES ====================

export interface ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export interface PaginatedResponse<T> extends ApiResponse<T[]> {
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}

// ==================== DASHBOARD TYPES ====================

export interface DashboardStats {
  totalResources: number;
  totalFindings: number;
  criticalFindings: number;
  highFindings: number;
  mediumFindings: number;
  lowFindings: number;
  remediationsGenerated: number;
  prsOpened: number;
  prsMerged: number;
  compliancePostures: CompliancePosture[];
  recentFindings: DashboardFinding[];
  remediationTrend: TrendPoint[];
  findingsTrend: TrendPoint[];
}

export interface DashboardFinding {
  id: string;
  title: string;
  severity: Severity;
  service: string;
  status: FindingStatus;
  resourceName: string;
  createdAt: string;
}

export interface TrendPoint {
  date: string;
  value: number;
}
