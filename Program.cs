/*
 * AppLockerEnum+CSV: Enumerador de políticas de AppLocker con parsing y export CSV
 * Compila: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /t:exe /out:EnumAppLocker.exe EnumAppLocker.cs
 * Ejecuta: execute-assembly EnumAppLocker.exe [--raw-xml] [--csv path\to\out.csv]
 */

using System;
using System.Linq;
using System.Text;
using System.ServiceProcess;
using Microsoft.Win32;
using System.Xml.Linq;
using System.Collections.Generic;
using System.IO;

public class AppLockerEnum
{
    private const string BaseKeyPath = @"SOFTWARE\Policies\Microsoft\Windows\SrpV2";
    private static readonly string[] RuleTypes = new[] { "Exe", "Msi", "Script", "Dll", "Appx" };

    public static void Main(string[] args)
    {
        bool dumpRawXml = args != null && args.Any(a => a.Equals("--raw-xml", StringComparison.OrdinalIgnoreCase));
        string csvPath = null;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i].Equals("--csv", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                {
                    csvPath = args[i + 1];
                    i++;
                }
                else
                {
                    csvPath = "applocker_enum.csv";
                }
            }
        }

        var sb = new StringBuilder();
        sb.AppendLine("[+] Enumerando políticas de AppLocker desde HKLM...");
        sb.AppendLine("    Colecciones: Exe, Msi, Script, Dll, Appx");
        sb.AppendLine();

        string serviceStatus = "unknown";
        try
        {
            var sc = new ServiceController("AppIDSvc");
            serviceStatus = sc.Status.ToString();
            sb.AppendLine("[i] AppIDSvc (Application Identity): " + serviceStatus);
        }
        catch
        {
            sb.AppendLine("[i] AppIDSvc no encontrado o sin permisos para consultar estado");
            serviceStatus = "not_found_or_no_permission";
        }
        sb.AppendLine();

        List<string> csvRows = null;
        if (!string.IsNullOrEmpty(csvPath))
        {
            csvRows = new List<string>();
            csvRows.Add("view,collection,guid,name,action,sid,condType,condValue,enforcement,serviceStatus,rawXml");
        }

        EnumerateView(RegistryView.Registry64, dumpRawXml, sb, csvRows, serviceStatus);
        EnumerateView(RegistryView.Registry32, dumpRawXml, sb, csvRows, serviceStatus);

        Console.WriteLine(sb.ToString());

        if (csvRows != null)
        {
            try
            {
                File.WriteAllLines(csvPath, csvRows, Encoding.UTF8);
                Console.WriteLine("[+] CSV escrito en: " + Path.GetFullPath(csvPath));
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Error escribiendo CSV: " + ex.Message);
            }
        }
    }

    private static void EnumerateView(RegistryView view, bool rawXml, StringBuilder sb, List<string> csvRows, string serviceStatus)
    {
        try
        {
            using (var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view).OpenSubKey(BaseKeyPath))
            {
                sb.AppendLine("[+] Vista de registro: " + view.ToString());
                if (baseKey == null)
                {
                    sb.AppendLine("    [!] Clave no encontrada en esta vista (posible que no haya GPO aplicada o que resida solo en la otra vista)");
                    sb.AppendLine();
                    return;
                }

                foreach (var ruleType in RuleTypes)
                {
                    using (var typeKey = baseKey.OpenSubKey(ruleType))
                    {
                        sb.AppendLine("");
                        sb.AppendLine("[--- " + ruleType.ToUpper() + " ---]");

                        if (typeKey == null)
                        {
                            sb.AppendLine("    (Colección ausente)");
                            continue;
                        }

                        var em = typeKey.GetValue("EnforcementMode");
                        string emText = "(desconocido)";
                        if (em is int)
                        {
                            switch ((int)em)
                            {
                                case 0: emText = "No configurado"; break;
                                case 1: emText = "Aplicado (Enforced)"; break;
                                case 2: emText = "Solo auditoría (AuditOnly)"; break;
                            }
                        }
                        sb.AppendLine("    EnforcementMode: " + emText);

                        var valueNames = typeKey.GetValueNames()
                                                .Where(v => v.StartsWith("{"))
                                                .OrderBy(v => v)
                                                .ToArray();

                        if (valueNames.Length == 0)
                        {
                            sb.AppendLine("    (No hay reglas definidas)");
                            continue;
                        }

                        int allowCount = 0, denyCount = 0;

                        foreach (var guid in valueNames)
                        {
                            var xml = typeKey.GetValue(guid) as string;
                            if (string.IsNullOrWhiteSpace(xml))
                            {
                                sb.AppendLine("    [!] " + guid + ": valor vacío");
                                continue;
                            }

                            string name = "n/a", action = "n/a", sid = "n/a", condType = "n/a", condValue = "n/a";
                            try
                            {
                                var doc = XDocument.Parse(xml, LoadOptions.PreserveWhitespace);
                                var ruleElem = doc.Root;

                                if (ruleElem != null)
                                {
                                    var attrName = ruleElem.Attribute("Name");
                                    var attrAction = ruleElem.Attribute("Action");
                                    var attrSid = ruleElem.Attribute("UserOrGroupSid");

                                    name = attrName != null ? attrName.Value : name;
                                    action = attrAction != null ? attrAction.Value : action;
                                    sid = attrSid != null ? attrSid.Value : sid;

                                    var cond = ruleElem.Element("Conditions") != null ? ruleElem.Element("Conditions").Elements().FirstOrDefault() : null;
                                    if (cond != null)
                                    {
                                        condType = cond.Name.LocalName;
                                        if (condType.Equals("FilePathCondition", StringComparison.OrdinalIgnoreCase))
                                        {
                                            var a = cond.Attribute("Path");
                                            condValue = a != null ? a.Value : condValue;
                                        }
                                        else if (condType.Equals("FilePublisherCondition", StringComparison.OrdinalIgnoreCase))
                                        {
                                            var pub = cond.Attribute("PublisherName") != null ? cond.Attribute("PublisherName").Value : null;
                                            var prod = cond.Attribute("ProductName") != null ? cond.Attribute("ProductName").Value : null;
                                            var file = cond.Attribute("FileName") != null ? cond.Attribute("FileName").Value : null;
                                            var lb = cond.Attribute("LowerBound") != null ? cond.Attribute("LowerBound").Value : null;
                                            var ub = cond.Attribute("UpperBound") != null ? cond.Attribute("UpperBound").Value : null;
                                            condValue = "Publisher='" + nv(pub) + "', Product='" + nv(prod) + "', File='" + nv(file) + "', Bounds=[" + nv(lb) + ".." + nv(ub) + "]";
                                        }
                                        else if (condType.Equals("FileHashCondition", StringComparison.OrdinalIgnoreCase))
                                        {
                                            var fh = cond.Descendants("FileHash").FirstOrDefault();
                                            var hash = fh != null && fh.Attribute("Hash") != null ? fh.Attribute("Hash").Value : (cond.Attribute("Hash") != null ? cond.Attribute("Hash").Value : null);
                                            condValue = hash != null ? hash : condValue;
                                        }
                                    }
                                }
                            }
                            catch (Exception px)
                            {
                                sb.AppendLine("    [!] " + guid + ": error parseando XML (" + px.Message + ")");
                            }

                            if (action.Equals("Allow", StringComparison.OrdinalIgnoreCase)) allowCount++;
                            else if (action.Equals("Deny", StringComparison.OrdinalIgnoreCase)) denyCount++;

                            sb.AppendLine("    Rule " + guid);
                            sb.AppendLine("      Name    : " + name);
                            sb.AppendLine("      Action  : " + action);
                            sb.AppendLine("      SID     : " + sid);
                            sb.AppendLine("      Cond    : " + condType);
                            sb.AppendLine("      Value   : " + condValue);

                            if (rawXml)
                            {
                                sb.AppendLine("      XML ----");
                                sb.AppendLine(Indent(xml, 8));
                                sb.AppendLine("      ---- XML");
                            }

                            if (csvRows != null)
                            {
                                string xmlNormalized = xml.Replace("\r\n", "\n").Replace("\r", "\n");
                                csvRows.Add(EscapeCsv(view.ToString())
                                          + "," + EscapeCsv(ruleType)
                                          + "," + EscapeCsv(guid)
                                          + "," + EscapeCsv(name)
                                          + "," + EscapeCsv(action)
                                          + "," + EscapeCsv(sid)
                                          + "," + EscapeCsv(condType)
                                          + "," + EscapeCsv(condValue)
                                          + "," + EscapeCsv(emText)
                                          + "," + EscapeCsv(serviceStatus)
                                          + "," + EscapeCsv(xmlNormalized));
                            }
                        }

                        sb.AppendLine("    Totales -> Allow: " + allowCount + " | Deny: " + denyCount);
                    }
                }
                sb.AppendLine();
            }
        }
        catch (Exception e)
        {
            sb.AppendLine("[X] Error en vista " + view.ToString() + ": " + e.Message);
            sb.AppendLine();
        }
    }

    private static string nv(string s) { return string.IsNullOrEmpty(s) ? "n/a" : s; }

    private static string Indent(string text, int spaces)
    {
        var pad = new string(' ', spaces);
        var lines = text.Replace("\r\n", "\n").Split('\n');
        var sb = new StringBuilder(text.Length + (spaces * lines.Length));
        for (int i = 0; i < lines.Length; i++) sb.Append(pad).AppendLine(lines[i]);
        return sb.ToString();
    }

    private static string EscapeCsv(string s)
    {
        if (s == null) return "\"\"";
        var replaced = s.Replace("\"", "\"\"");
        replaced = replaced.Replace("\r", "\\r").Replace("\n", "\\n");
        return "\"" + replaced + "\"";
    }
}
