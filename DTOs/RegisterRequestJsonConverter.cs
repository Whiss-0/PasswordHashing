using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Api.DTOs
{
    public sealed class RegisterRequestJsonConverter : JsonConverter<RegisterRequest>
    {
        public override RegisterRequest Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType != JsonTokenType.StartObject)
            {
                throw new JsonException("Expected start of object.");
            }

            var dto = new RegisterRequest();
            var comparison = options.PropertyNameCaseInsensitive ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndObject)
                {
                    return dto;
                }

                if (reader.TokenType != JsonTokenType.PropertyName)
                {
                    throw new JsonException("Expected property name.");
                }

                var propertyName = reader.GetString();
                reader.Read();

                if (string.IsNullOrEmpty(propertyName))
                {
                    reader.Skip();
                    continue;
                }

                if (propertyName.Equals("username", comparison))
                {
                    dto.Username = ReadString(ref reader, options);
                    continue;
                }

                if (propertyName.Equals("password", comparison))
                {
                    dto.Password = ReadString(ref reader, options);
                    continue;
                }

                if (propertyName.Equals("email", comparison))
                {
                    dto.Email = ReadString(ref reader, options);
                    continue;
                }

                reader.Skip();
            }

            throw new JsonException("Expected end of object.");
        }

        public override void Write(Utf8JsonWriter writer, RegisterRequest value, JsonSerializerOptions options)
        {
            writer.WriteStartObject();
            writer.WriteString("username", value.Username);
            writer.WriteString("password", value.Password);
            writer.WriteString("email",    value.Email);
            writer.WriteEndObject();
        }

        private static string ReadString(ref Utf8JsonReader reader, JsonSerializerOptions options)
        {
            if (reader.TokenType == JsonTokenType.String)
            {
                return reader.GetString() ?? string.Empty;
            }

            return JsonSerializer.Deserialize<string>(ref reader, options) ?? string.Empty;
        }

        private static int ReadInt32(ref Utf8JsonReader reader, JsonSerializerOptions options)
        {
            if (reader.TokenType == JsonTokenType.Number && reader.TryGetInt32(out var intValue))
            {
                return intValue;
            }

            if (reader.TokenType == JsonTokenType.String && int.TryParse(reader.GetString(), out var parsed))
            {
                return parsed;
            }

            return JsonSerializer.Deserialize<int>(ref reader, options);
        }
    }
}