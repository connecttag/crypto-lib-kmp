# ConnectTag Crypto Suite Library (crypto-lib-kmp)

[![JitPack](https://jitpack.io/v/connecttag/crypto-lib-kmp.svg)](https://jitpack.io/#connecttag/crypto-lib-kmp)

مكتبة التشفير والأمن السيبراني متعددة المنصات (Kotlin Multiplatform):
- **Android** (API 24+)
- **Desktop JVM** (Windows, macOS, Linux)
- **iOS** (Arm64, SimulatorArm64)

---

## 📦 التثبيت والإضافة للمشروع (Installation via JitPack)

### 1. إضافة مستودع JitPack في `settings.gradle.kts`:
```kotlin
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
}
```

### 2. إضافة التبعية في `build.gradle.kts`:
```kotlin
kotlin {
    sourceSets {
        commonMain.dependencies {
            // For Kotlin Multiplatform:
            implementation("com.github.connecttag.crypto-lib-kmp:crypto-lib-kmp:1.0.0")
        }
    }
}
```

الحزمة الأساسية للمكتبة: `org.connecttag.lib.crypto.*` أو `org.connecttag.lib.core.crypto.*`

---

## 🌟 الميزات الأساسية

1. **`AESCipher` & `AesUtils`:**
   - تشفير وفك تشفير متقدم بنمط AES-CBC متوافق عبر منصات Android و Desktop JVM.
2. **`BroadcastCryptoUtils`:**
   - توقيع رقمي وتحقق عبر HMAC-SHA256 وتشفير متقدم بنمط AES-GCM للبيانات الحساسة وحزم البث.
3. **`RSACipher` & `RsaUtils`:**
   - توليد أزواج مفاتيح RSA (Public/Private Keypairs)، وتشفير وفك تشفير الرسائل غير المتناظرة.
4. **`DigestUtils` & `HashUtils`:**
   - دوال التجزئة والبصمات الرقمية الموحدة (SHA-256, SHA-1, MD5) للملفات والمدخلات النصية ومصفوفات البايت عبر Android, Desktop, iOS.
5. **`Base64Utils`:**
   - محول Base64 نقي متعدد المنصات بدون أي اعتماديات خارجية لمعالجة السلاسل النصية ومصفوفات البايت.
