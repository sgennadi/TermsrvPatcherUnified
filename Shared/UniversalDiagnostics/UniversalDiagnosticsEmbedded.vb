Imports System
Imports System.Collections.Generic
Imports System.Globalization
Imports System.IO
Imports System.Runtime.InteropServices
Imports System.Security.Cryptography
Imports System.Text
Imports System.Text.Json
Imports System.Text.RegularExpressions
Imports System.Threading

' Canonical source: sgennadi/UniversalDiagnocticsModule/embedded/dotnet/
' Embedded directly in each .NET app; no collector EXE, token, HTTP or GitHub access.
' Compatible with universal_diagnostics.core.capture() (schema v1).
Public NotInheritable Class UniversalDiagnosticsEmbedded
    Private Sub New()
    End Sub

    Public Const Schema As String = "universal-diagnostics/v1"

    Public NotInheritable Class Receipt
        Public Property Id As String = ""
        Public Property Path As String = ""
    End Class

    Private Shared Function Clean(value As String, maxLength As Integer) As String
        Dim text = If(value, "").Replace(ChrW(0), " ")
        If text.Length > maxLength * 3 Then text = text.Substring(0, maxLength * 3)
        text = Regex.Replace(text, "\x1b\[[0-9;]*[a-zA-Z]", "", RegexOptions.CultureInvariant)
        ' Drop complete credential-bearing lines before substituting identifiers.
        text = Regex.Replace(text,
            "(?im)^.*\b(?:password|passwd|passphrase|pwd|recovery[\s_-]*(?:key|password)|" &
            "bitlocker[\s_-]*(?:key|password)|laps[\s_-]*password|access[\s_-]*token|" &
            "refresh[\s_-]*token|authorization|bearer|client[\s_-]*secret|api[\s_-]*key|" &
            "private[\s_-]*key|github_pat_|gh[pousr]_)\b.*$",
            "[REDACTED: confidential line]", RegexOptions.CultureInvariant)
        For Each pair In New (Pattern As String, Replacement As String)() {
            ("(?i)\b\d{6}(?:-\d{6}){7}\b", "[BITLOCKER-KEY]"),
            ("(?i)\b(?:github_pat_[A-Za-z0-9_]{15,}|gh[pousr]_[A-Za-z0-9_]{15,})\b", "[TOKEN]"),
            ("(?i)https?://[^\s<>""']+", "[URL]"),
            ("(?i)\\\\[^\s<>""']+", "[NETWORK-PATH]"),
            ("(?i)(?<![A-Za-z0-9])[A-Z]:\\[^\s""']+", "[WINDOWS-PATH]"),
            ("(?i)(?:/home/|/Users/|/root/)[^\s""']+", "[USER-PATH]"),
            ("(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[EMAIL]"),
            ("(?i)\bS-1-\d+(?:-\d+){2,}\b", "[SID]"),
            ("(?i)\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b", "[GUID]"),
            ("(?i)\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IPV4]"),
            ("(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b", "[MAC]"),
            ("(?i)\b[A-Za-z0-9_.-]{2,70}\\[A-Za-z0-9_.-]{2,70}\b", "[DOMAIN-ACCOUNT]"),
            ("(?i)\b(?:CN|OU|DC)=[^\s,;]+(?:,(?:CN|OU|DC)=[^\s,;]+)*", "[LDAP-DN]")
        }
            text = Regex.Replace(text, pair.Pattern, pair.Replacement, RegexOptions.CultureInvariant)
        Next
        text = Regex.Replace(text, "[\r\n\t]+", " ", RegexOptions.CultureInvariant).Trim()
        If text.Length > maxLength Then text = text.Substring(0, maxLength)
        Return If(text.Length = 0, "unspecified", text)
    End Function

    Private Shared Function Field(obj As JsonElement, key As String,
                                  fallback As String, length As Integer) As String
        Dim value As JsonElement
        If Not obj.TryGetProperty(key, value) OrElse
           value.ValueKind = JsonValueKind.Null Then
            Return Clean(fallback, length)
        End If
        If value.ValueKind <> JsonValueKind.String AndAlso
           value.ValueKind <> JsonValueKind.Number AndAlso
           value.ValueKind <> JsonValueKind.True AndAlso
           value.ValueKind <> JsonValueKind.False Then
            Throw New InvalidDataException("Invalid diagnostic metadata type.")
        End If
        Return Clean(If(value.ValueKind = JsonValueKind.String, value.GetString(),
                        value.ToString()), length)
    End Function

    Private Shared Function Digest(value As String) As String
        Return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).
            ToLowerInvariant()
    End Function

    Public Shared Function QueueDirectory(project As String) As String
        If String.IsNullOrWhiteSpace(project) OrElse
           Not Regex.IsMatch(project,
             "^[A-Za-z0-9][A-Za-z0-9_.-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$") OrElse
           project.Contains("..", StringComparison.Ordinal) Then
            Throw New ArgumentException("Invalid diagnostics project identity.")
        End If
        Dim root = Environment.GetEnvironmentVariable("UDX_STATE_DIR")
        If String.IsNullOrWhiteSpace(root) Then
            root = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "UniversalDiagnostics")
        End If
        Return System.IO.Path.Combine(System.IO.Path.GetFullPath(root),
                    Digest(project.ToLowerInvariant()).Substring(0, 16))
    End Function

    Private Shared Function ArchitectureName() As String
        Select Case RuntimeInformation.OSArchitecture
            Case Architecture.X64
                Return "AMD64"
            Case Architecture.X86
                Return "x86"
            Case Architecture.Arm64
                Return "ARM64"
            Case Else
                Return RuntimeInformation.OSArchitecture.ToString()
        End Select
    End Function

    Public Shared Function Capture(payload As String,
                         Optional token As CancellationToken = Nothing) As Receipt
        token.ThrowIfCancellationRequested()
        If String.IsNullOrWhiteSpace(payload) OrElse
           Encoding.UTF8.GetByteCount(payload) > 65536 Then
            Throw New InvalidDataException("Diagnostic payload is empty or too large.")
        End If
        Using document = JsonDocument.Parse(payload)
            Dim root = document.RootElement
            If root.ValueKind <> JsonValueKind.Object Then
                Throw New InvalidDataException("Expected diagnostics metadata object.")
            End If
            Dim project = Field(root, "project", "", 140)
            Dim folder = QueueDirectory(project)
            Dim component = Field(root, "component", "Application", 90)
            Dim errorType = Field(root, "error_type", "Error", 90)
            Dim code = Field(root, "code", "unknown", 60)
            Dim level = Field(root, "level", "error", 10).ToLowerInvariant()
            If level <> "error" AndAlso level <> "warning" AndAlso level <> "info" Then
                Throw New InvalidDataException("Invalid diagnostics severity.")
            End If
            Dim reportId = Guid.NewGuid().ToString("D")
            Dim fingerprint = Digest(String.Join("|", {
                project.ToLowerInvariant(), component.ToLowerInvariant(),
                errorType.ToLowerInvariant(), code.ToLowerInvariant()
            }))
            Dim entry As New Dictionary(Of String, Object) From {
                {"schema", Schema},
                {"id", reportId},
                {"timestamp_utc", DateTime.UtcNow.ToString(
                    "yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture)},
                {"project", project},
                {"component", component},
                {"error_type", errorType},
                {"code", code},
                {"level", level},
                {"version", Field(root, "version", "unknown", 70)},
                {"summary", Field(root, "summary", "No description supplied", 450)},
                {"platform", If(OperatingSystem.IsWindows(), "Windows", "Other")},
                {"architecture", ArchitectureName()},
                {"fingerprint", fingerprint}
            }
            Dim record As New Dictionary(Of String, Object) From {
                {"event", entry},
                {"delivery", New Dictionary(Of String, String) From {
                    {"status", "pending"}, {"url", ""}
                }}
            }
            Dim bytes = JsonSerializer.SerializeToUtf8Bytes(record,
                New JsonSerializerOptions With {.WriteIndented = True})
            If bytes.Length > 65536 Then
                Throw New InvalidDataException("Diagnostic record too large.")
            End If
            token.ThrowIfCancellationRequested()
            Directory.CreateDirectory(folder)
            Dim destination = System.IO.Path.Combine(folder, reportId & ".json")
            Dim staging = System.IO.Path.Combine(folder,
                ".udx-" & Guid.NewGuid().ToString("N") & ".tmp")
            Try
                Using output As New FileStream(staging, FileMode.CreateNew,
                                              FileAccess.Write, FileShare.None)
                    output.Write(bytes)
                    output.Flush(True)
                End Using
                token.ThrowIfCancellationRequested()
                File.Move(staging, destination)
                Return New Receipt With {.Id = reportId, .Path = destination}
            Finally
                If File.Exists(staging) Then File.Delete(staging)
            End Try
        End Using
    End Function
End Class
