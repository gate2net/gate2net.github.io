{{- define "intergate.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "intergate.fullname" -}}
{{- $name := include "intergate.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "intergate.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{ include "intergate.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "intergate.selectorLabels" -}}
app.kubernetes.io/name: {{ include "intergate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* SSH clients reach intergate only through Traefik with PROXY protocol. */}}
{{- define "intergate.proxyProtocol" -}}
{{- and .Values.traefik.enabled .Values.traefik.ssh.enabled .Values.traefik.ssh.proxyProtocol (not .Values.sshService.enabled) -}}
{{- end -}}

{{/* intergate terminates TLS, Traefik passes it through. */}}
{{- define "intergate.passthrough" -}}
{{- if and .Values.traefik.enabled .Values.traefik.tls.passthrough -}}
{{- if or .Values.traefik.tls.certResolver .Values.traefik.tls.secretName .Values.certManager.enabled -}}
{{- fail "traefik.tls.passthrough lets intergate get its certificates: leave traefik.tls.certResolver, traefik.tls.secretName and certManager unset" -}}
{{- end -}}
true
{{- else -}}
false
{{- end -}}
{{- end -}}

{{/* The domain and its direct subdomains, as a Go regular expression. */}}
{{- define "intergate.hostRegexp" -}}
^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.{{ .Values.domain | replace "." "\\." }}$
{{- end -}}

{{- define "intergate.tlsSecret" -}}
{{- if .Values.traefik.tls.secretName -}}
{{- .Values.traefik.tls.secretName -}}
{{- else if .Values.certManager.enabled -}}
{{- printf "%s-tls" (include "intergate.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "intergate.secretName" -}}
{{- if .Values.existingSecret -}}
{{- .Values.existingSecret -}}
{{- else if .Values.secretEnv -}}
{{- include "intergate.fullname" . -}}
{{- end -}}
{{- end -}}
