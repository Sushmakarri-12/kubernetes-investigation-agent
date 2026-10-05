"""
Heuristic and pattern detection rules for Kubernetes failure modes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from .models import RemediationStep, Severity


@dataclass
class InvestigationRule:
    rule_id: str
    category: str
    title: str
    severity: Severity
    patterns: List[re.Pattern]
    description_template: str
    confidence: float
    remediations: List[RemediationStep] = field(default_factory=list)
    exclude_patterns: List[re.Pattern] = field(default_factory=list)

    def matches(self, text: str) -> Optional[re.Match]:
        for exc in self.exclude_patterns:
            if exc.search(text):
                return None
        for pattern in self.patterns:
            m = pattern.search(text)
            if m:
                return m
        return None


def get_default_rules() -> List[InvestigationRule]:
    return [
        # 1. Out of Memory (OOMKilled)
        InvestigationRule(
            rule_id="OOM_KILLED_EXIT_137",
            category="MEMORY_EXHAUSTION",
            title="Container Terminated by OOM Killer (Exit Code 137)",
            severity=Severity.CRITICAL,
            patterns=[
                re.compile(r"exit(?:ed)?\s+(?:with\s+)?code\s+137\b", re.IGNORECASE),
                re.compile(r"\bOOMKilled\b", re.IGNORECASE),
                re.compile(r"Out of memory:\s*Kill(?:ed)? process", re.IGNORECASE),
                re.compile(r"invoked oom-killer", re.IGNORECASE),
                re.compile(r"cgroup out of memory", re.IGNORECASE),
                re.compile(r"Memory cgroup out of memory", re.IGNORECASE),
                re.compile(r"java\.lang\.OutOfMemoryError", re.IGNORECASE),
                re.compile(r"JavaScript heap out of memory", re.IGNORECASE),
                re.compile(r"fatal error:\s*runtime:\s*out of memory", re.IGNORECASE),
            ],
            description_template="Container exceeded its cgroup memory limit or node memory was exhausted, resulting in kernel SIGKILL (exit code 137).",
            confidence=0.98,
            remediations=[
                RemediationStep(
                    action="Increase Container Memory Limits",
                    command="kubectl patch deployment <deployment-name> -p '{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"<container-name>\",\"resources\":{\"limits\":{\"memory\":\"<new-limit>\"},\"requests\":{\"memory\":\"<new-request>\"}}}]}}}}'",
                    explanation="Bump the container's memory limit in spec.containers[].resources.limits.memory if valid traffic caused higher memory usage.",
                    step_type="immediate",
                ),
                RemediationStep(
                    action="Inspect Memory Consumption History",
                    command="kubectl top pod <pod-name> --containers",
                    explanation="Monitor memory utilization trend to distinguish between sudden memory leak and expected memory spike.",
                    step_type="diagnostic",
                ),
                RemediationStep(
                    action="Profile Application Heap",
                    command="kubectl exec -it <pod-name> -- <heap-dump-command>",
                    explanation="Investigate potential memory leaks, unclosed resources, or excessive cache sizes in the application code.",
                    step_type="architectural",
                ),
            ],
        ),

        # 2. CrashLoopBackOff
        InvestigationRule(
            rule_id="CRASH_LOOP_BACKOFF",
            category="CRASH_LOOP",
            title="Container CrashLoopBackOff",
            severity=Severity.CRITICAL,
            patterns=[
                re.compile(r"\bCrashLoopBackOff\b", re.IGNORECASE),
                re.compile(r"Back-off restarting failed container", re.IGNORECASE),
                re.compile(r"restarting failed container .* in pod", re.IGNORECASE),
            ],
            description_template="The container is terminating repeatedly upon startup, triggering Kubernetes exponential backoff delay.",
            confidence=0.95,
            remediations=[
                RemediationStep(
                    action="Retrieve Previous Crashed Container Logs",
                    command="kubectl logs <pod-name> --previous",
                    explanation="Check the logs of the container instance immediately before the crash occurred to pinpoint initialization errors.",
                    step_type="immediate",
                ),
                RemediationStep(
                    action="Inspect Pod Status and Exit Code",
                    command="kubectl describe pod <pod-name>",
                    explanation="View State, Last State, Reason, and Exit Code in pod description.",
                    step_type="diagnostic",
                ),
            ],
        ),

        # 3. Liveness Probe Failure
        InvestigationRule(
            rule_id="LIVENESS_PROBE_FAILED",
            category="PROBE_FAILURE",
            title="Liveness Probe Failed",
            severity=Severity.HIGH,
            patterns=[
                re.compile(r"Liveness probe failed", re.IGNORECASE),
                re.compile(r"Container .* failed liveness probe, will be restarted", re.IGNORECASE),
                re.compile(r"killing pod .* container .* failed liveness probe", re.IGNORECASE),
            ],
            description_template="Kubernetes liveness probe failed repeatedly, causing the kubelet to restart the container.",
            confidence=0.95,
            remediations=[
                RemediationStep(
                    action="Inspect Liveness Probe Thresholds",
                    command="kubectl get pod <pod-name> -o jsonpath='{.spec.containers[*].livenessProbe}'",
                    explanation="Verify if timeoutSeconds, initialDelaySeconds, or failureThreshold are too aggressive for the workload under load.",
                    step_type="diagnostic",
                ),
                RemediationStep(
                    action="Tune Initial Delay and Timeout",
                    command="kubectl patch deployment <deployment-name> -p '{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"<container>\",\"livenessProbe\":{\"initialDelaySeconds\":30,\"timeoutSeconds\":5}}]}}}}'",
                    explanation="Provide adequate time for application warmup before triggering health check terminations.",
                    step_type="immediate",
                ),
            ],
        ),

        # 4. Readiness Probe Failure
        InvestigationRule(
            rule_id="READINESS_PROBE_FAILED",
            category="PROBE_FAILURE",
            title="Readiness Probe Failed (Pod Removed from Service Endpoints)",
            severity=Severity.HIGH,
            patterns=[
                re.compile(r"Readiness probe failed", re.IGNORECASE),
                re.compile(r"Readiness probe errored:.*HTTP probe failed with statuscode:\s*(?:5\d\d|4\d\d)", re.IGNORECASE),
                re.compile(r"Readiness probe failed:\s*Get\s*.*connection refused", re.IGNORECASE),
                re.compile(r"Readiness probe failed:\s*context deadline exceeded", re.IGNORECASE),
            ],
            description_template="Readiness probe failed, causing Kubernetes to temporarily unroute service traffic from this pod.",
            confidence=0.92,
            remediations=[
                RemediationStep(
                    action="Check Service Endpoints Status",
                    command="kubectl get endpoints <service-name>",
                    explanation="Check if any backend pods remain ready to receive user traffic.",
                    step_type="diagnostic",
                ),
                RemediationStep(
                    action="Inspect Health Check Endpoint Internals",
                    command="kubectl exec -it <pod-name> -- curl -v http://localhost:<port>/healthz",
                    explanation="Test the readiness endpoint from within the pod to isolate network issues from application-level health check dependencies (e.g. database ping).",
                    step_type="diagnostic",
                ),
            ],
        ),

        # 5. Image Pull Failure
        InvestigationRule(
            rule_id="IMAGE_PULL_FAILURE",
            category="IMAGE_PULL_FAILURE",
            title="Container Image Pull Failure (ImagePullBackOff / ErrImagePull)",
            severity=Severity.HIGH,
            patterns=[
                re.compile(r"\bImagePullBackOff\b", re.IGNORECASE),
                re.compile(r"\bErrImagePull\b", re.IGNORECASE),
                re.compile(r"manifest for .* not found", re.IGNORECASE),
                re.compile(r"repository does not exist", re.IGNORECASE),
                re.compile(r"failed to resolve reference", re.IGNORECASE),
                re.compile(r"toomanyrequests:\s*You have reached your pull rate limit", re.IGNORECASE),
                re.compile(r"failed to pull and unpack image", re.IGNORECASE),
            ],
            description_template="Kubelet failed to pull container image from container registry due to invalid image tag, authentication failure, or registry rate limiting.",
            confidence=0.96,
            remediations=[
                RemediationStep(
                    action="Verify Container Image Tag and Name",
                    command="kubectl get pod <pod-name> -o jsonpath='{.spec.containers[*].image}'",
                    explanation="Ensure image repository, name, and tag are correct and exist in the target registry.",
                    step_type="diagnostic",
                ),
                RemediationStep(
                    action="Check Image Pull Secrets",
                    command="kubectl get secret <image-pull-secret> -o yaml",
                    explanation="Ensure imagePullSecrets are configured with active registry credentials in the pod's namespace.",
                    step_type="immediate",
                ),
            ],
        ),

        # 6. DNS Resolution Failure
        InvestigationRule(
            rule_id="DNS_RESOLUTION_FAILURE",
            category="DNS_FAILURE",
            title="Kubernetes In-Cluster DNS Resolution Failure",
            severity=Severity.HIGH,
            patterns=[
                re.compile(r"dial tcp:\s*lookup .* no such host", re.IGNORECASE),
                re.compile(r"getaddrinfo:\s*Name or service not known", re.IGNORECASE),
                re.compile(r"Temporary failure in name resolution", re.IGNORECASE),
                re.compile(r"DNS resolution failed for", re.IGNORECASE),
                re.compile(r"CoreDNS.*server failure", re.IGNORECASE),
                re.compile(r"SERVFAIL", re.IGNORECASE),
            ],
            description_template="Application failed to resolve hostname or Kubernetes cluster service DNS name.",
            confidence=0.90,
            remediations=[
                RemediationStep(
                    action="Check CoreDNS Health and Logs",
                    command="kubectl logs -n kube-system -l k8s-app=kube-dns",
                    explanation="Verify if CoreDNS pods are running healthy and not crashing or throttling DNS requests.",
                    step_type="diagnostic",
                ),
                RemediationStep(
                    action="Validate In-Pod DNS Configuration",
                    command="kubectl exec -it <pod-name> -- cat /etc/resolv.conf",
                    explanation="Confirm nameserver points to the cluster DNS service IP (usually 10.96.0.10).",
                    step_type="diagnostic",
                ),
            ],
        ),

        # 7. Network / Connection Refused / Timeout
        InvestigationRule(
            rule_id="NETWORK_CONNECTION_REFUSED",
            category="NETWORK_CONNECTIVITY",
            title="Network Connection Refused or Timed Out",
            severity=Severity.HIGH,
            patterns=[
                re.compile(r"connect:\s*connection refused", re.IGNORECASE),
                re.compile(r"read:\s*connection reset by peer", re.IGNORECASE),
                re.compile(r"dial tcp .* connect:\s*no route to host", re.IGNORECASE),
                re.compile(r"upstream connect error or disconnect/reset before headers", re.IGNORECASE),
                re.compile(r"HTTP 502 Bad Gateway", re.IGNORECASE),
                re.compile(r"HTTP 504 Gateway Timeout", re.IGNORECASE),
                re.compile(r"context deadline exceeded\s+\(Client\.Timeout", re.IGNORECASE),
            ],
            exclude_patterns=[
                re.compile(r"(?:readiness|liveness|startup)\s+probe", re.IGNORECASE),
            ],
            description_template="Downstream or upstream TCP connection failure; target port closed, pod not ready, or network policy blocking communication.",
            confidence=0.88,
            remediations=[
                RemediationStep(
                    action="Check NetworkPolicies in Target Namespace",
                    command="kubectl get networkpolicy -n <namespace>",
                    explanation="Check if an ingress/egress NetworkPolicy restricts traffic between caller and callee pods.",
                    step_type="diagnostic",
                ),
                RemediationStep(
                    action="Verify Target Pod Readiness and Listening Port",
                    command="kubectl get pods -o wide -l app=<target-app>",
                    explanation="Confirm the target service pods are in Ready 1/1 state and listening on the designated containerPort.",
                    step_type="immediate",
                ),
            ],
        ),

        # 8. RBAC / Authorization Forbidden
        InvestigationRule(
            rule_id="RBAC_PERMISSION_DENIED",
            category="RBAC_AUTHORIZATION",
            title="Kubernetes API RBAC Authorization Denied (403 Forbidden)",
            severity=Severity.MEDIUM,
            patterns=[
                re.compile(r"is forbidden:\s*User \"[^\"]+\" cannot (?:get|list|watch|create|update|patch|delete)", re.IGNORECASE),
                re.compile(r"403 Forbidden.*system:serviceaccount:", re.IGNORECASE),
                re.compile(r"RBAC:\s*access denied", re.IGNORECASE),
                re.compile(r"Unauthorized:.*system:anonymous", re.IGNORECASE),
            ],
            description_template="The pod's ServiceAccount lacks sufficient RBAC Role/ClusterRole permissions to perform the requested Kubernetes API operation.",
            confidence=0.96,
            remediations=[
                RemediationStep(
                    action="Check ServiceAccount Permissions with Can-I",
                    command="kubectl auth can-i <verb> <resource> --as=system:serviceaccount:<namespace>:<serviceaccount>",
                    explanation="Validate if the pod's serviceaccount is authorized for the desired API group and verb.",
                    step_type="diagnostic",
                ),
                RemediationStep(
                    action="Grant Missing RoleBinding or ClusterRoleBinding",
                    command="kubectl create rolebinding <binding-name> --clusterrole=<role-name> --serviceaccount=<namespace>:<sa-name> -n <namespace>",
                    explanation="Attach the necessary Role or ClusterRole to the workload's ServiceAccount.",
                    step_type="immediate",
                ),
            ],
        ),

        # 9. Storage / PVC Mount Failures
        InvestigationRule(
            rule_id="VOLUME_MOUNT_FAILURE",
            category="STORAGE_VOLUME",
            title="Volume Mount / PersistentVolumeClaim Failure",
            severity=Severity.HIGH,
            patterns=[
                re.compile(r"FailedMount", re.IGNORECASE),
                re.compile(r"MountVolume\.SetUp failed for volume", re.IGNORECASE),
                re.compile(r"Unable to attach or mount volumes", re.IGNORECASE),
                re.compile(r"no space left on device", re.IGNORECASE),
                re.compile(r"Read-only file system", re.IGNORECASE),
                re.compile(r"Multi-Attach error for volume", re.IGNORECASE),
            ],
            description_template="Volume mount failure: disk full, ReadWriteOnce volume already attached to another node, or CSI storage driver failure.",
            confidence=0.94,
            remediations=[
                RemediationStep(
                    action="Inspect PVC and PV Status",
                    command="kubectl describe pvc <pvc-name>",
                    explanation="Check if the PersistentVolumeClaim is Bound and review storage provisioner events.",
                    step_type="diagnostic",
                ),
                RemediationStep(
                    action="Inspect Node Disk Pressure",
                    command="kubectl describe node <node-name> | grep -A 5 Conditions",
                    explanation="Check if DiskPressure condition is True on the hosting node.",
                    step_type="diagnostic",
                ),
            ],
        ),

        # 10. Application Exception / Panic / Stack Trace
        InvestigationRule(
            rule_id="APPLICATION_PANIC_OR_CRASH",
            category="APPLICATION_EXCEPTION",
            title="Unhandled Application Exception or Kernel Panic",
            severity=Severity.HIGH,
            patterns=[
                re.compile(r"\bpanic:\s+", re.IGNORECASE),
                re.compile(r"Traceback \(most recent call last\):", re.IGNORECASE),
                re.compile(r"NullPointerException", re.IGNORECASE),
                re.compile(r"Segmentation fault \(core dumped\)", re.IGNORECASE),
                re.compile(r"exit(?:ed)?\s+(?:with\s+)?code\s+139\b", re.IGNORECASE),
                re.compile(r"fatal error:\s*", re.IGNORECASE),
                re.compile(r"UnhandledPromiseRejectionWarning", re.IGNORECASE),
            ],
            description_template="Application crashed due to an unhandled exception, null pointer dereference, or memory segmentation fault.",
            confidence=0.91,
            remediations=[
                RemediationStep(
                    action="Review Application Stack Trace",
                    command="kubectl logs <pod-name> --previous",
                    explanation="Trace the exact source file and line number causing the uncaught exception.",
                    step_type="diagnostic",
                ),
            ],
        ),

        # 11. Resource / Thread Exhaustion
        InvestigationRule(
            rule_id="THREAD_OR_CONNECTION_EXHAUSTION",
            category="RESOURCE_EXHAUSTION",
            title="Thread Pool or Connection Pool Exhaustion",
            severity=Severity.HIGH,
            patterns=[
                re.compile(r"too many open files", re.IGNORECASE),
                re.compile(r"connection pool exhausted", re.IGNORECASE),
                re.compile(r"thread pool exhausted", re.IGNORECASE),
                re.compile(r"deadlock detected", re.IGNORECASE),
                re.compile(r"database connection pool timeout", re.IGNORECASE),
            ],
            description_template="Workload exhausted system file descriptors, thread limits, or database pool connections.",
            confidence=0.89,
            remediations=[
                RemediationStep(
                    action="Tune Connection Pool Max Size & Timeout",
                    command="kubectl describe configmap <app-config>",
                    explanation="Increase database pool size or connection idle timeout settings.",
                    step_type="architectural",
                ),
            ],
        ),
    ]
