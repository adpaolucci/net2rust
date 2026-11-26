use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedCod {
    pub raw: u32,
    pub format_type: u8,
    pub major_class: &'static str,
    pub minor_class: String,
    pub services: Vec<String>,
    pub summary: String,
}

pub fn decode_cod(cod: u32) -> DecodedCod {
    let format_type = (cod & 0x03) as u8;
    if format_type != 0 {
        let summary = format!("Non-standard CoD format ({format_type}) [0x{cod:06X}]");
        return DecodedCod {
            raw: cod,
            format_type,
            major_class: "Reserved",
            minor_class: format!("Format {format_type}"),
            services: Vec::new(),
            summary,
        };
    }

    let mut services = Vec::new();
    const SERVICE_BITS: &[(u32, &str)] = &[
        (13, "Limited Discoverable Mode"),
        (14, "LE Audio"),
        (15, "Reserved"),
        (16, "Positioning"),
        (17, "Networking"),
        (18, "Rendering"),
        (19, "Capturing"),
        (20, "Object Transfer"),
        (21, "Audio"),
        (22, "Telephony"),
        (23, "Information"),
    ];
    for &(bit, label) in SERVICE_BITS {
        if (cod & (1u32 << bit)) != 0 {
            services.push(label.to_string());
        }
    }

    let major_code = (cod >> 8) & 0x1F;
    let minor_code = (cod >> 2) & 0x3F;

    let major_class = match major_code {
        0x00 => "Miscellaneous",
        0x01 => "Computer",
        0x02 => "Phone",
        0x03 => "LAN/Network Access Point",
        0x04 => "Audio/Video",
        0x05 => "Peripheral",
        0x06 => "Imaging",
        0x07 => "Wearable",
        0x08 => "Toy",
        0x09 => "Health",
        0x1F => "Uncategorized",
        _ => "Reserved",
    };

    let minor_class = decode_minor_class(major_code, minor_code);

    let summary = if minor_class.is_empty() || minor_class == "Uncategorized" {
        major_class.to_string()
    } else {
        format!("{major_class}: {minor_class}")
    };

    DecodedCod {
        raw: cod,
        format_type,
        major_class,
        minor_class,
        services,
        summary,
    }
}

fn decode_minor_class(major: u32, minor: u32) -> String {
    match major {
        0x00 => "Uncategorized".to_string(),
        0x01 => match minor {
            0x00 => "Uncategorized",
            0x01 => "Desktop Workstation",
            0x02 => "Server-class Computer",
            0x03 => "Laptop",
            0x04 => "Handheld PC/PDA",
            0x05 => "Palm-size PC/PDA",
            0x06 => "Wearable Computer",
            0x07 => "Tablet",
            _ => "Reserved",
        }
        .to_string(),
        0x02 => match minor {
            0x00 => "Uncategorized",
            0x01 => "Cellular",
            0x02 => "Cordless",
            0x03 => "Smartphone",
            0x04 => "Wired Modem or Voice Gateway",
            0x05 => "Common ISDN Access",
            _ => "Reserved",
        }
        .to_string(),
        0x03 => {
            let load = match (minor >> 3) & 0x07 {
                0 => "Fully available",
                1 => "1-17% utilized",
                2 => "17-33% utilized",
                3 => "33-50% utilized",
                4 => "50-67% utilized",
                5 => "67-83% utilized",
                6 => "83-99% utilized",
                _ => "No service available",
            };
            load.to_string()
        }
        0x04 => match minor {
            0x00 => "Uncategorized",
            0x01 => "Wearable Headset",
            0x02 => "Hands-free Device",
            0x04 => "Microphone",
            0x05 => "Loudspeaker",
            0x06 => "Headphones",
            0x07 => "Portable Audio",
            0x08 => "Car Audio",
            0x09 => "Set-top Box",
            0x0A => "HiFi Audio Device",
            0x0B => "VCR",
            0x0C => "Video Camera",
            0x0D => "Camcorder",
            0x0E => "Video Monitor",
            0x0F => "Video Display and Loudspeaker",
            0x10 => "Video Conferencing",
            0x12 => "Gaming/Toy",
            _ => "Reserved",
        }
        .to_string(),
        0x05 => {
            let primary = match (minor >> 4) & 0x03 {
                0b01 => Some("Keyboard"),
                0b10 => Some("Pointing Device"),
                0b11 => Some("Combo Keyboard/Pointing"),
                _ => None,
            };
            let sub = match minor & 0x0F {
                0x00 => None,
                0x01 => Some("Joystick"),
                0x02 => Some("Gamepad"),
                0x03 => Some("Remote Control"),
                0x04 => Some("Sensing Device"),
                0x05 => Some("Digitizer Tablet"),
                0x06 => Some("Card Reader"),
                0x07 => Some("Digital Pen"),
                0x08 => Some("Handheld Scanner"),
                0x09 => Some("Handheld Gestural Input"),
                _ => Some("Reserved"),
            };
            match (primary, sub) {
                (Some(p), Some(s)) => format!("{p} ({s})"),
                (Some(p), None) => p.to_string(),
                (None, Some(s)) => s.to_string(),
                (None, None) => "Uncategorized".to_string(),
            }
        }
        0x06 => {
            let mut flags = Vec::new();
            if (minor & 0x04) != 0 {
                flags.push("Display");
            }
            if (minor & 0x08) != 0 {
                flags.push("Camera");
            }
            if (minor & 0x10) != 0 {
                flags.push("Scanner");
            }
            if (minor & 0x20) != 0 {
                flags.push("Printer");
            }
            if flags.is_empty() {
                "Uncategorized".to_string()
            } else {
                flags.join("/")
            }
        }
        0x07 => match minor {
            0x01 => "Wristwatch",
            0x02 => "Pager",
            0x03 => "Jacket",
            0x04 => "Helmet",
            0x05 => "Glasses",
            0x06 => "Pin",
            _ => "Uncategorized",
        }
        .to_string(),
        0x08 => match minor {
            0x01 => "Robot",
            0x02 => "Vehicle",
            0x03 => "Doll/Action Figure",
            0x04 => "Controller",
            0x05 => "Game",
            _ => "Uncategorized",
        }
        .to_string(),
        0x09 => match minor {
            0x00 => "Undefined",
            0x01 => "Blood Pressure Monitor",
            0x02 => "Thermometer",
            0x03 => "Weighing Scale",
            0x04 => "Glucose Meter",
            0x05 => "Pulse Oximeter",
            0x06 => "Heart/Pulse Rate Monitor",
            0x07 => "Health Data Display",
            0x08 => "Step Counter",
            0x09 => "Body Composition Analyzer",
            0x0A => "Peak Flow Monitor",
            0x0B => "Medication Monitor",
            0x0C => "Knee Prosthesis",
            0x0D => "Ankle Prosthesis",
            0x0E => "Generic Health Manager",
            0x0F => "Personal Mobility Device",
            _ => "Reserved",
        }
        .to_string(),
        _ => "Uncategorized".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_cod_major_classes() {
        // Laptop computer with Networking + Object Transfer
        let laptop = decode_cod(0x1A010C);
        assert_eq!(laptop.format_type, 0);
        assert_eq!(laptop.major_class, "Computer");
        assert_eq!(laptop.minor_class, "Laptop");
        assert!(laptop.services.contains(&"Networking".to_string()));
        assert!(laptop.services.contains(&"Object Transfer".to_string()));

        // Headphones (Audio/Video 0x04, minor 0x06, Audio bit 21 + Rendering bit 18)
        let headphones = decode_cod(0x240418);
        assert_eq!(headphones.major_class, "Audio/Video");
        assert_eq!(headphones.minor_class, "Headphones");
        assert!(headphones.services.contains(&"Audio".to_string()));
        assert!(headphones.services.contains(&"Rendering".to_string()));

        // Smartphone (Phone 0x02, minor 0x03)
        let phone = decode_cod((0x02 << 8) | (0x03 << 2) | (1 << 22));
        assert_eq!(phone.major_class, "Phone");
        assert_eq!(phone.minor_class, "Smartphone");
        assert!(phone.services.contains(&"Telephony".to_string()));

        // Combo Keyboard/Pointing + Gamepad (Peripheral 0x05, minor 0b11_0010 = 0x32)
        let combo = decode_cod((0x05 << 8) | (0x32 << 2));
        assert_eq!(combo.major_class, "Peripheral");
        assert_eq!(combo.minor_class, "Combo Keyboard/Pointing (Gamepad)");

        // Imaging Printer + Scanner (Imaging 0x06, minor 0x30)
        let imaging = decode_cod((0x06 << 8) | (0x30 << 2));
        assert_eq!(imaging.major_class, "Imaging");
        assert_eq!(imaging.minor_class, "Scanner/Printer");

        // Wearable Wristwatch (0x07, minor 0x01)
        let watch = decode_cod((0x07 << 8) | (0x01 << 2));
        assert_eq!(watch.major_class, "Wearable");
        assert_eq!(watch.minor_class, "Wristwatch");

        // Toy Robot (0x08, minor 0x01)
        let toy = decode_cod((0x08 << 8) | (0x01 << 2));
        assert_eq!(toy.major_class, "Toy");
        assert_eq!(toy.minor_class, "Robot");

        // Health Pulse Oximeter (0x09, minor 0x05)
        let health = decode_cod((0x09 << 8) | (0x05 << 2));
        assert_eq!(health.major_class, "Health");
        assert_eq!(health.minor_class, "Pulse Oximeter");

        // Non-standard format type
        let non_std = decode_cod(0x000001);
        assert_eq!(non_std.format_type, 1);
        assert_eq!(non_std.major_class, "Reserved");
    }
}
