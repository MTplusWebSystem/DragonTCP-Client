# Guia de Build para Android

O DragonTCP Client é projetado para ser compilado como uma biblioteca compartilhada Android (`.so`) e embutido em um aplicativo Android via interface JNI/NDK.

---

## Pré-requisitos

| Requisito | Versão | Observações |
|-----------|--------|-------------|
| Go | 1.26+ | Com suporte a CGO |
| Android NDK | 30 (30.0.14904198) | Detectado automaticamente; outras versões podem funcionar |
| PowerShell | 5.1+ | Apenas host de build Windows |

---

## Build Rápido

```powershell
# Padrão: arm64-v8a (dispositivos Android modernos)
.\build.ps1

# Todos os ABIs
.\build.ps1 -Abi all

# ABI específico com NDK personalizado
.\build.ps1 -Abi arm64-v8a -NdkPath "C:\Android\ndk\30.0.14904198"

# API level e pasta de saída personalizados
.\build.ps1 -Abi arm64-v8a -ApiLevel 30 -OutputDir "saida"
```

---

## Alvos ABI Suportados

| ABI | GOARCH | Toolchain | Dispositivos |
|-----|--------|-----------|--------------|
| `arm64-v8a` | `arm64` | `aarch64-linux-android30-clang` | Android 64-bit moderno (principal) |
| `armeabi-v7a` | `arm` (GOARM=7) | `armv7a-linux-androideabi30-clang` | Dispositivos ARM 32-bit antigos |
| `x86_64` | `amd64` | `x86_64-linux-android30-clang` | Emuladores, tablets x86 |
| `x86` | `386` | `i686-linux-android30-clang` | Emuladores x86 legados |

---

## Saída do Build

```
builds/
+-- arm64-v8a/
|   +-- libdragontcp_client.so      <- caminho compatível com jniLibs
+-- armeabi-v7a/
|   +-- libdragontcp_client.so
+-- x86_64/
|   +-- libdragontcp_client.so
+-- x86/
|   +-- libdragontcp_client.so
+-- libdragontcp_client-arm64-v8a.so     <- nomenclatura plana
+-- libdragontcp_client-armeabi-v7a.so
+-- libdragontcp_client-x86_64.so
+-- libdragontcp_client-x86.so
+-- libdragontcp_client.so               <- cópia principal (último ABI compilado)
```

O script também copia automaticamente para `../../../android/lib/<ABI>/libdragontcp_client.so` se o diretório existir, seguindo o layout padrão `jniLibs` de projetos Android:

```
android/
+-- lib/
    +-- arm64-v8a/
    |   +-- libdragontcp_client.so
    +-- armeabi-v7a/
    |   +-- libdragontcp_client.so
    +-- ...
```

---

## Modo de Build: `pie`

A biblioteca é compilada com `-buildmode=pie` (Position Independent Executable), obrigatório para Android 5.0+ (`minSdkVersion 21`). Isso habilita ASLR e satisfaz os requisitos de segurança do Android para bibliotecas nativas carregadas via `System.loadLibrary`.

---

## Configuração CGO

O script define estas variáveis de ambiente para cada alvo:

```
CGO_ENABLED=1
GOOS=android
GOARCH=<arch-alvo>
GOARM=7        (somente armeabi-v7a)
CC=<caminho-clang-ndk>
```

Flags do linker: `-s -w` (remove símbolos de debug e DWARF, minimizando o tamanho do binário).

---

## Detecção Automática do NDK

O script sonda estes caminhos em ordem:

1. Parâmetro `-NdkPath` (override explícito)
2. Variável de ambiente `ANDROID_NDK_HOME`
3. Variável de ambiente `ANDROID_NDK_ROOT`
4. Variável de ambiente `NDK_HOME`
5. `%LOCALAPPDATA%\Android\Sdk\ndk\30.0.14904198`
6. `%LOCALAPPDATA%\Android\Sdk\ndk-bundle`
7. Todos os subdiretórios de `%LOCALAPPDATA%\Android\Sdk\ndk\` (ordem decrescente por nome)

O primeiro caminho que contiver `toolchains\llvm\prebuilt\windows-x86_64\bin\` é usado.

---

## Integrando em um App Android

### Gradle (`app/build.gradle`)

```groovy
android {
    sourceSets {
        main {
            jniLibs.srcDirs = ['lib']
        }
    }
}
```

### Kotlin / Java

```kotlin
class DragonTCPClient {
    companion object {
        init {
            System.loadLibrary("dragontcp_client")
        }

        // Declare métodos nativos conforme necessário
        // A biblioteca expõe um ponto de entrada equivalente ao main do Go
        external fun startProxy(args: Array<String>): Int
    }
}
```

> **Nota:** O ponto de entrada exportado e a interface JNI dependem do código wrapper do lado Android. Consulte o projeto Android para as ligações JNI exatas.

---

## Solução de Problemas

### NDK Não Encontrado

```
[X] Android NDK nao encontrado!
```

Instale o NDK via Android Studio: **SDK Manager → SDK Tools → NDK (Side by side)**, selecione a versão 30.

### Compilador Não Encontrado para ABI

```
[X] Compilador nao encontrado para arm64-v8a em: ...
```

Verifique se a versão do NDK corresponde ao API level 30. O nome do binário Clang inclui o API level: `aarch64-linux-android30-clang.cmd`.

### Falha no Build Go

Certifique-se de que `CGO_ENABLED=1` está definido e que o binário Clang do NDK está acessível. No Windows, os scripts `.cmd` wrapper no diretório bin do NDK chamam o cross-compilador Linux real.

### Verificar Build

```powershell
# Listar arquivos gerados com tamanhos
Get-ChildItem -Recurse builds\ -Filter "*.so" |
  Select-Object Name, @{N="MB";E={[math]::Round($_.Length/1MB,2)}}
```
