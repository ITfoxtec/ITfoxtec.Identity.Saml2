using System;

namespace ITfoxtec.Identity.Saml2
{
    public static class DateTimeExtensions
    {
        public static DateTimeOffset ToDateTimeOffsetOutOfRangeProtected(this DateTime dateTime)
        {
            var utcDateTime = dateTime.ToUniversalTime();
            if(utcDateTime <= DateTimeOffset.MinValue.UtcDateTime)
            {
                return DateTimeOffset.MinValue;
            }
            else if (utcDateTime >= DateTimeOffset.MaxValue.UtcDateTime)
            {
                return DateTimeOffset.MaxValue;
            }
            else
            {
                return new DateTimeOffset(dateTime);
            }
        }
    }
}
