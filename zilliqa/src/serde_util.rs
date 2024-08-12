pub mod num_as_str {
    use std::{fmt::Display, str::FromStr};

    use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: ToString,
    {
        value.to_string().serialize(serializer)
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: FromStr,
        T::Err: Display,
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

pub mod bool_as_str {
    use serde::{
        de::{self, Unexpected},
        Deserialize, Deserializer,
    };

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
        let s = String::deserialize(d)?;
        let b = s
            .parse()
            .map_err(|_| de::Error::invalid_value(Unexpected::Str(&s), &"a boolean"))?;
        Ok(b)
    }
}

pub mod json_value_as_str {
    use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
    use serde_json::Value;

    pub fn serialize<S>(value: &Value, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.to_string().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        serde_json::from_str(
            &String::deserialize(deserializer)?
        ).map_err(de::Error::custom)
    }
}
