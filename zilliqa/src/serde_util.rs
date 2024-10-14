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
        serde_json::from_str(&String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Custom (de)serializer for `Vec<ParamValue>` which doesn't rely on `deserialize_any` by serializing the inner
/// `serde_json::Value` as a string. This means bincode is able to handle it.
pub mod vec_param_value {
    use serde::{ser::SerializeSeq, Deserialize, Deserializer, Serialize, Serializer};

    use crate::scilla::ParamValue;

    pub fn serialize<S>(values: &Vec<ParamValue>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct ParamValueEncoded<'s> {
            #[serde(rename = "vname")]
            pub name: &'s str,
            pub value: String,
            #[serde(rename = "type")]
            pub ty: &'s str,
        }

        let mut serializer = serializer.serialize_seq(Some(values.len()))?;
        for value in values {
            let encoded = ParamValueEncoded {
                name: &value.name,
                value: serde_json::to_string(&value.value).unwrap(),
                ty: &value.ty,
            };
            serializer.serialize_element(&encoded)?;
        }
        serializer.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<ParamValue>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ParamValueEncoded {
            #[serde(rename = "vname")]
            pub name: String,
            pub value: String,
            #[serde(rename = "type")]
            pub ty: String,
        }

        let values = <Vec<ParamValueEncoded>>::deserialize(deserializer)?
            .into_iter()
            .map(|value| ParamValue {
                name: value.name,
                value: serde_json::from_str(&value.value).unwrap(),
                ty: value.ty,
            })
            .collect();

        Ok(values)
    }
}
