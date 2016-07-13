using ITfoxtec.Identity.Saml2.Schemas;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace ITfoxtec.Identity.Saml2.Util
{
    internal class RawSaml2QueryString
    {
        Dictionary<string, string> queryValues = new Dictionary<string, string>();

        public string MessageName { get; private set; }

        public RawSaml2QueryString(string queryString, string messageName)
        {
            MessageName = messageName;
            Read(queryString);
        }

        private RawSaml2QueryString Read(string queryString)
        {
            var match = Regex.Match(queryString, @"\?(?<key>[^=^&]+)=(?<value>[^=^&]+)(&(?<key>[^=^&]+)=(?<value>[^=^&]+))+");
            if (!match.Success || match.Groups["key"] == null || match.Groups["value"] == null)
            {
                throw new InvalidDataException("Invalid Query String.");
            }

            for (var i = 0; i < match.Groups["key"].Captures.Count; i++)
            {
                ReadValue(match, i, MessageName);
                ReadValue(match, i, Saml2Constants.Message.RelayState);
                ReadValue(match, i, Saml2Constants.Message.SigAlg);
            }

            if (!(queryValues.Count == 2 || queryValues.Count == 3))
            {
                throw new InvalidDataException("Invalid Query String.");
            }

            return this;
        }

        private void ReadValue(Match match, int i, string key)
        {
            if (key.Equals(match.Groups["key"].Captures[i].Value, StringComparison.InvariantCultureIgnoreCase))
            {
                queryValues.Add(key, match.Groups["value"].Captures[i].Value);
            }
        }

        public string SignedQueryString
        {
            get
            {
                return string.Join("&", GetSignedQueryString());
            }
        }

        private IEnumerable<string> GetSignedQueryString()
        {
            yield return string.Join("=", MessageName, queryValues[MessageName]);

            if (queryValues.ContainsKey(Saml2Constants.Message.RelayState))
            {
                yield return string.Join("=", Saml2Constants.Message.RelayState, queryValues[Saml2Constants.Message.RelayState]);
            }

            yield return string.Join("=", Saml2Constants.Message.SigAlg, queryValues[Saml2Constants.Message.SigAlg]);
        }

    }
}
