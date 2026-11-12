{{/* Expand the chart name. */}}
{{- define "runebox.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified app name. */}}
{{- define "runebox.fullname" -}}
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

{{/* Common labels. */}}
{{- define "runebox.labels" -}}
app.kubernetes.io/name: {{ include "runebox.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- end -}}

{{/* Selector labels. */}}
{{- define "runebox.selectorLabels" -}}
app.kubernetes.io/name: {{ include "runebox.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Service account name. */}}
{{- define "runebox.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "runebox.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Image tag: image.tag, or the release tag ("v" + appVersion) images are published under. */}}
{{- define "runebox.imageTag" -}}
{{- default (printf "v%s" .Chart.AppVersion) .Values.image.tag -}}
{{- end -}}

{{/* Container image reference. */}}
{{- define "runebox.image" -}}
{{- printf "%s:%s" .Values.image.repository (include "runebox.imageTag" .) -}}
{{- end -}}

{{/* Egress sidecar image: egress.image, or the matching runebox-egress release. */}}
{{- define "runebox.egressImage" -}}
{{- default (printf "%s-egress:%s" .Values.image.repository (include "runebox.imageTag" .)) .Values.egress.image -}}
{{- end -}}

{{/* StorageClass for direct-assigned kata-fc workspaces: the configured one, or the chart driver's. */}}
{{- define "runebox.directVolumeClass" -}}
{{- if .Values.sandbox.directVolumeStorageClass -}}
{{- .Values.sandbox.directVolumeStorageClass -}}
{{- else if .Values.sandbox.directVolumeDriver.enabled -}}
{{- .Values.sandbox.directVolumeDriver.storageClassName -}}
{{- end -}}
{{- end -}}

{{/* Name of the profiles Secret (existing or chart-created). */}}
{{- define "runebox.profilesSecretName" -}}
{{- if .Values.profiles.existingSecret -}}
{{- .Values.profiles.existingSecret -}}
{{- else -}}
{{- printf "%s-profiles" (include "runebox.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Volume source for the profiles mount. Profiles can contain secret material, so
the chart stores them in a Secret by default. An existing ConfigMap is still
honored for backward compatibility.
*/}}
{{- define "runebox.profilesVolume" -}}
{{- if .Values.profiles.existingConfigMap -}}
configMap:
  name: {{ .Values.profiles.existingConfigMap }}
  optional: true
{{- else -}}
secret:
  secretName: {{ include "runebox.profilesSecretName" . }}
  optional: true
{{- end -}}
{{- end -}}

{{/* Name of the server API token Secret (existing or chart-created). */}}
{{- define "runebox.serverTokenSecretName" -}}
{{- default (printf "%s-server-token" (include "runebox.fullname" .)) .Values.server.auth.existingSecret -}}
{{- end -}}

{{/* Name of the server TLS Secret (existing or chart-created). */}}
{{- define "runebox.serverTLSSecretName" -}}
{{- default (printf "%s-server-tls" (include "runebox.fullname" .)) .Values.server.tls.existingSecret -}}
{{- end -}}
