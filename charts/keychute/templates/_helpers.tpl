{{/*
Chart name, overridable by nameOverride.
*/}}
{{- define "keychute.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully-qualified app name. Truncated to 63 chars for label/DNS limits.
*/}}
{{- define "keychute.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Chart name and version, as used by the helm.sh/chart label.
*/}}
{{- define "keychute.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels.
*/}}
{{- define "keychute.labels" -}}
helm.sh/chart: {{ include "keychute.chart" . }}
{{ include "keychute.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels. Immutable across upgrades — a Deployment's selector cannot be
changed in place.
*/}}
{{- define "keychute.selectorLabels" -}}
app.kubernetes.io/name: {{ include "keychute.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app: {{ include "keychute.fullname" . }}
{{- end -}}

{{/*
ServiceAccount name. Bound to system:auth-delegator so the server may create
TokenReviews for SA-token client authentication (DESIGN.md §7).
*/}}
{{- define "keychute.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "keychute.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Fully-qualified server image reference. Prefers an explicit digest (set by CI)
over a tag.
*/}}
{{- define "keychute.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag }}
{{- end -}}
{{- end -}}

{{/*
In-cluster DNS name of the Service. Internal clients dial this over TLS, and
it is the SAN the internal-CA certificate must carry.
*/}}
{{- define "keychute.serviceFQDN" -}}
{{ include "keychute.fullname" . }}.{{ .Values.namespace }}.svc.cluster.local
{{- end -}}

{{/*
Name of the HTTPRoute the gateway generates for our Ingress. The cluster
materializes Ingresses as Envoy Gateway HTTPRoutes with the generated name
`<ingress>-<host-with-dashes>` (DESIGN.md §7); the OIDC SecurityPolicy targets
that route.
*/}}
{{- define "keychute.httpRouteName" -}}
{{- if .Values.ingress.oidc.httpRouteName -}}
{{- .Values.ingress.oidc.httpRouteName -}}
{{- else -}}
{{- printf "%s-%s" (include "keychute.fullname" .) (.Values.ingress.host | replace "." "-") | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/*
Comma-separated list of every Secret the server loads at STARTUP, for the
Stakater Reloader annotation: a change to any of them needs a pod recreate to
take effect (nothing is re-read at runtime).
*/}}
{{- define "keychute.reloadSecrets" -}}
{{- $secrets := list .Values.tls.secretName .Values.kek.secretName -}}
{{- if .Values.database.urlSecret -}}
{{- $secrets = append $secrets .Values.database.urlSecret -}}
{{- else -}}
{{- $secrets = append $secrets .Values.database.existingSecret -}}
{{- end -}}
{{- if .Values.pushover.enabled -}}
{{- $secrets = append $secrets .Values.pushover.secretName -}}
{{- end -}}
{{- if .Values.upstreamCA.secretName -}}
{{- $secrets = append $secrets .Values.upstreamCA.secretName -}}
{{- end -}}
{{- if .Values.database.sslRootCertSecret -}}
{{- $secrets = append $secrets .Values.database.sslRootCertSecret -}}
{{- end -}}
{{- range (include "keychute.provisionedSecretNames" . | fromJsonArray) -}}
{{- $secrets = append $secrets . -}}
{{- end -}}
{{- $secrets | uniq | join "," -}}
{{- end -}}

{{/*
JSON array of the distinct Kubernetes Secrets that provisioned secrets read
from (`valueFrom`, `injection.usernameFrom`, `injection.accessKeyIdFrom`).
Each is mounted at /etc/keychute/provisioned/<secretName>.
*/}}
{{- define "keychute.provisionedSecretNames" -}}
{{- $names := list -}}
{{- range .Values.secrets -}}
{{- if not .valueFrom -}}
{{- fail (printf "keychute: secrets[%s] needs valueFrom.secretName and valueFrom.key" .name) -}}
{{- end -}}
{{- $names = append $names .valueFrom.secretName -}}
{{- with .injection -}}
{{- with .usernameFrom -}}{{- $names = append $names .secretName -}}{{- end -}}
{{- with .accessKeyIdFrom -}}{{- $names = append $names .secretName -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- $names | uniq | toJson -}}
{{- end -}}

{{/*
Volume name for a provisioned-secret mount: stable and DNS-label safe
whatever the Secret is called.
*/}}
{{- define "keychute.provisionedVolume" -}}
prov-{{ . | sha256sum | trunc 12 }}
{{- end -}}
