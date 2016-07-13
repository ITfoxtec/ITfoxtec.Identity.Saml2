using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace ITfoxtec.Identity.Saml2
{
    public static class Saml2BindingExtensions
    {
        /// <summary>
        /// Set a Dictionary of key value pairs as a Query string in the Relay State.
        /// </summary>
        public static string SetRelayStateQuery<T>(this Saml2Binding<T> saml2Binding, Dictionary<string, string> elements)
        {
            if(elements == null)
            {
                throw new ArgumentNullException(nameof(elements));
            }

            saml2Binding.RelayState = string.Join("&", ElementsToStrings(elements));
            return saml2Binding.RelayState;
        }

        private static IEnumerable<string> ElementsToStrings(Dictionary<string, string> elements)
        {
            foreach (var element in elements)
            {
                yield return string.Join("=", element.Key, Uri.EscapeDataString(element.Value));
            }
        }

        /// <summary>
        /// Get the Relay State Query string as a Dictionary of key value pairs.
        /// </summary>
        public static Dictionary<string, string> GetRelayStateQuery<T>(this Saml2Binding<T> saml2Binding)
        {
            Dictionary<string, string> elements = new Dictionary<string,string>();
            if(string.IsNullOrWhiteSpace(saml2Binding.RelayState))
            {
                return elements;
            }

            var match = Regex.Match(saml2Binding.RelayState, @"(?<key>[^=^&]+)=(?<value>[^=^&]*)(&(?<key>[^=^&]+)=(?<value>[^=^&]*))*");
            if (!match.Success || match.Groups["key"] == null || match.Groups["value"] == null)
            {
                throw new InvalidDataException("Invalid Relay State Query.");
            }

            for (var i = 0; i < match.Groups["key"].Captures.Count; i++)
            {
                elements.Add(match.Groups["key"].Captures[i].Value, Uri.UnescapeDataString(match.Groups["value"].Captures[i].Value));
            }
            return elements;
        }
    }
}
