# Automation & DevSecOps Cheatsheet

| Category | Tool/Process | Command/Example | Notes |
|----------|--------------|-----------------|-------|
| **CI/CD Security** ||||
| Secret scanning | GitLeaks | `gitleaks detect --source=.` | Identify leaked credentials in code |
| SAST | SonarQube | `sonar-scanner` | Static code analysis |
| Container scanning | Trivy | `trivy image alpine:3.15` | Find container vulnerabilities |
| Dependency checking | OWASP Dependency-Check | `dependency-check --project MyApp --scan app/` | Identify vulnerable dependencies |
| IaC scanning | Checkov | `checkov -d terraform/` | Find misconfigurations in IaC |
| **Infrastructure Automation** ||||
| Configuration management | Ansible | `ansible-playbook -i inventory deploy.yml` | Maintain consistent configurations |
| Infrastructure as Code | Terraform | `terraform apply -auto-approve` | Provision cloud resources |
| Containerization | Docker | `docker-compose up -d` | Containerize applications |
| Orchestration | Kubernetes | `kubectl apply -f deployment.yaml` | Container orchestration |
| Immutable infrastructure | Packer | `packer build template.json` | Create reusable machine images |
| **Monitoring & Observability** ||||
| Log aggregation | ELK Stack | `filebeat modules enable nginx` | Centralize and analyze logs |
| Metrics collection | Prometheus | `prometheus --config.file=prometheus.yml` | Time-series metrics |
| Visualization | Grafana | `grafana-server --config=/etc/grafana/config.ini` | Dashboards for metrics |
| Alerting | Alertmanager | `alertmanager --config.file=alertmanager.yml` | Alert notification system |
| Tracing | Jaeger | `docker run -d --name jaeger jaegertracing/all-in-one` | Distributed tracing |
| **Continuous Testing** ||||
| Unit testing | Pytest | `pytest --cov=myapp tests/` | Test individual components |
| Integration testing | Robot Framework | `robot tests/` | Test component interactions |
| Load testing | JMeter | `jmeter -n -t test-plan.jmx -l results.jtl` | Verify performance under load |
| API testing | Postman | `newman run collection.json -e environment.json` | Test API endpoints |
| Security testing | OWASP ZAP | `zap-cli quick-scan --self-contained --start-options "-config api.disablekey=true" https://target.com` | Automated security scans |
| **Deployment Strategies** ||||
| Blue/Green | Deployment tools | `kubectl apply -f blue-green-service.yaml` | Zero downtime deployment |
| Canary releases | Service mesh | `istioctl apply -f canary-deployment.yaml` | Limited exposure testing |
| Feature flags | LaunchDarkly | `ldclient.variation("new-feature", user, false)` | Controlled feature rollout |
| Rollbacks | Version control | `kubectl rollout undo deployment/app` | Quickly revert changes |
| GitOps | ArgoCD | `argocd app sync myapp` | Git as source of truth |
| **Security Automation** ||||
| Compliance as Code | InSpec | `inspec exec profile --reporter cli json:results.json` | Automated compliance checks |
| Threat modeling | Threat Dragon | Automated reviews in PR pipeline | Early security assessment |
| Security patching | Dependabot | Automated PR for dependency updates | Keep dependencies current |
| Secret management | HashiCorp Vault | `vault kv get -field=password secret/app` | Secure secrets storage |
| WAF automation | AWS WAF + CDK | `cdk deploy waf-stack` | Auto-deployed web protection |
| **Pipeline Automation** ||||
| CI triggers | GitHub Actions | `on: [push, pull_request]` | Automate pipeline execution |
| Pipeline as Code | Jenkins | `Jenkinsfile` with pipeline DSL | Version-controlled pipelines |
| Release automation | GoCD | `gocd.yaml` pipeline definition | Automated delivery |
| ChatOps | Slack + webhooks | `/deploy production v1.2.3` | Chat-based operations |
| Approval gates | ServiceNow integration | Automated ticket creation and checks | Governance controls |

## Common Automation Scripts & One-liners

| Task | Script/Command | Purpose |
|------|----------------|---------|
| Find outdated dependencies | `npm outdated --json \| jq` | Identify update needs |
| Auto-format code | `prettier --write "src/**/*.{js,jsx}"` | Enforce code style |
| Update Docker images | `docker images --format "{{.Repository}}:{{.Tag}}" \| xargs -L1 docker pull` | Keep images current |
| Clean old containers | `docker system prune -af` | Free up resources |
| Auto-generate docs | `swagger-codegen generate -i api-spec.yaml -l html2` | Keep docs updated |
| Health check | `curl -s -o /dev/null -w "%{http_code}" https://service/health` | Verify service status |
| Auto-renew certificates | `certbot renew --post-hook "systemctl reload nginx"` | Maintain valid TLS |
| Performance benchmark | `ab -n 1000 -c 50 https://service/api` | Test under load |
