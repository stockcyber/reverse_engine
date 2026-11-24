![REVERSE LAB Banner](./banner.png)

<h1 align="center">REVERSE LAB</h1>

<p align="center">
  Advanced Executable Analysis & Reverse Engineering Toolkit.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
</p>

<p align="center">
  <b>Developed by Stock</b>
</p>

---

<p align="center">
  <a href="#-português">🇧🇷 Português</a> •
  <a href="#-english">🇺🇸 English</a> •
  <a href="#-日本語">🇯🇵 日本語</a>
</p>

---

## 🇧🇷 Português

### 📌 Sobre o projeto

O **REVERSE LAB** é uma ferramenta desenvolvida em Python com o objetivo de facilitar a análise interna de executáveis e a identificação de tecnologias utilizadas em sua compilação.

O projeto reúne recursos de extração automatizada, identificação de arquivos embutidos e integração com ferramentas de engenharia reversa, tudo em um único ambiente interativo diretamente no terminal.

### ⚙️ Funcionalidades

- **PE Resource Extraction** — Extração de recursos internos de executáveis Windows, incluindo ícones, imagens, manifestos e textos.
- **File Carving** — Identificação e extração de arquivos embutidos através de assinaturas binárias.
- **PyInstaller Extraction** — Identificação e extração de pacotes PyInstaller, módulos e arquivos Python compilados.
- **Technology Detection** — Identificação de tecnologias como Python, .NET, Electron, Java, Unity, Go e Rust.
- **Ghidra Integration** — Análise e decompilação de funções para pseudocódigo C.
- **Rizin Integration** — Extração de informações, strings, funções e assembly.
- **Cutter Integration** — Abertura de executáveis em uma interface gráfica de análise.
- **Tool Manager** — Instalação, gerenciamento e remoção de ferramentas externas.
- **Automatic Reports** — Geração de relatórios com informações sobre os arquivos analisados.

### 🛠️ Ferramentas integradas

| Ferramenta | Função |
|---|---|
| Ghidra | Engenharia reversa e decompilação |
| Rizin | Análise de binários e assembly |
| Cutter | Interface gráfica para análise |
| JDK 21 | Ambiente necessário para o Ghidra |

### 📥 Instalação

Clone o repositório:

```bash
git clone https://github.com/SEU-USUARIO/Reverse-Lab.git
```

Entre na pasta:

```bash
cd Reverse-Lab
```

Execute:

```bash
python reverse_engine.py
```

**Dependências:** o núcleo do projeto utiliza bibliotecas padrão do Python. Não é necessário instalar pacotes adicionais com pip para executar a extração básica.

### 🚀 Como utilizar

**Interface interativa:**

```bash
python reverse_engine.py
```

**Análise básica:**

```bash
python reverse_engine.py programa.exe
```

**Análise com Rizin:**

```bash
python reverse_engine.py programa.exe --rizin
```

**Análise com Ghidra:**

```bash
python reverse_engine.py programa.exe --ghidra
```

**Análise com todas as ferramentas:**

```bash
python reverse_engine.py programa.exe --tudo
```

**Verificar ferramentas instaladas:**

```bash
python reverse_engine.py --status
```

### 📂 Estrutura de saída

```text
programa_extraido/
│
├── recursos/
│   ├── icones/
│   ├── imagens/
│   ├── html/
│   └── manifest.xml
│
├── embutidos/
├── pyinstaller/
├── ghidra/
├── rizin/
└── LEIAME.txt
```

A estrutura pode variar de acordo com o formato do executável e as ferramentas selecionadas.

### 🔒 Segurança

O Reverse Lab foi desenvolvido para analisar arquivos sem executar o programa analisado durante o processo de extração e análise.

Também possui mecanismos de proteção para caminhos de arquivos extraídos e limites para processamento de arquivos ZIP.

**Importante:** a análise de executáveis desconhecidos ainda pode apresentar riscos. Utilize ambientes isolados e analise somente arquivos próprios, open source ou para os quais você tenha autorização.

### 💻 Tecnologias utilizadas

- Python
- PE (Portable Executable)
- PyInstaller
- Ghidra
- Rizin
- Cutter
- Java JDK 21

---

## 🇺🇸 English

### 📌 About

**REVERSE LAB** is a Python-based tool designed to simplify executable analysis and identify the technologies used to build compiled applications.

The project combines automated resource extraction, embedded file identification, and integration with reverse engineering tools into a single interactive terminal environment.

### ⚙️ Features

- **PE Resource Extraction** — Extracts internal resources from Windows executables, including icons, images, manifests, and text.
- **File Carving** — Identifies and extracts embedded files using binary signatures.
- **PyInstaller Extraction** — Detects and extracts PyInstaller packages, modules, and compiled Python files.
- **Technology Detection** — Identifies technologies such as Python, .NET, Electron, Java, Unity, Go, and Rust.
- **Ghidra Integration** — Analyzes and decompiles functions into C-like pseudocode.
- **Rizin Integration** — Extracts information, strings, functions, and assembly.
- **Cutter Integration** — Opens executables in a graphical analysis interface.
- **Tool Manager** — Installs, manages, and removes external tools.
- **Automatic Reports** — Generates reports containing information about analyzed files.

### 🛠️ Integrated tools

| Tool | Purpose |
|---|---|
| Ghidra | Reverse engineering and decompilation |
| Rizin | Binary and assembly analysis |
| Cutter | Graphical analysis interface |
| JDK 21 | Required environment for Ghidra |

### 📥 Installation

Clone the repository:

```bash
git clone https://github.com/YOUR-USERNAME/Reverse-Lab.git
```

Navigate to the project directory:

```bash
cd Reverse-Lab
```

Run the application:

```bash
python reverse_engine.py
```

**Dependencies:** the core application uses Python standard libraries. No additional pip packages are required for basic extraction.

### 🚀 How to use

**Interactive interface:**

```bash
python reverse_engine.py
```

**Basic analysis:**

```bash
python reverse_engine.py program.exe
```

**Analysis with Rizin:**

```bash
python reverse_engine.py program.exe --rizin
```

**Analysis with Ghidra:**

```bash
python reverse_engine.py program.exe --ghidra
```

**Analysis with all tools:**

```bash
python reverse_engine.py program.exe --tudo
```

**Check installed tools:**

```bash
python reverse_engine.py --status
```

### 📂 Output structure

```text
program_extracted/
│
├── resources/
│   ├── icons/
│   ├── images/
│   ├── html/
│   └── manifest.xml
│
├── embedded/
├── pyinstaller/
├── ghidra/
├── rizin/
└── README.txt
```

The output structure may vary depending on the executable format and selected tools.

### 🔒 Security

Reverse Lab is designed to analyze files without executing the analyzed program during the extraction and analysis process.

It also includes protections for extracted file paths and processing limits for ZIP archives.

**Important:** analyzing unknown executables may still involve risks. Use isolated environments and only analyze files you own, open-source files, or files you are authorized to inspect.

### 💻 Technologies used

- Python
- PE (Portable Executable)
- PyInstaller
- Ghidra
- Rizin
- Cutter
- Java JDK 21

---

## 🇯🇵 日本語

### 📌 プロジェクトについて

**REVERSE LAB** は、実行ファイルの内部解析や、コンパイルに使用された技術の特定を簡単にするために Python で開発されたツールです。

リソースの自動抽出、埋め込みファイルの検出、リバースエンジニアリングツールとの連携機能を、ターミナル上の一つの対話型環境に統合しています。

### ⚙️ 主な機能

- **PE Resource Extraction** — Windows 実行ファイルからアイコン、画像、マニフェスト、テキストなどのリソースを抽出します。
- **File Carving** — バイナリシグネチャを使用して埋め込みファイルを検出・抽出します。
- **PyInstaller Extraction** — PyInstaller パッケージ、モジュール、コンパイル済み Python ファイルを検出・抽出します。
- **Technology Detection** — Python、.NET、Electron、Java、Unity、Go、Rust などの技術を識別します。
- **Ghidra Integration** — 関数を解析し、C 言語風の疑似コードに逆コンパイルします。
- **Rizin Integration** — 情報、文字列、関数、アセンブリを抽出します。
- **Cutter Integration** — 実行ファイルを GUI の解析環境で開きます。
- **Tool Manager** — 外部ツールのインストール、管理、削除を行います。
- **Automatic Reports** — 解析したファイルの情報を含むレポートを自動生成します。

### 🛠️ 統合ツール

| ツール | 機能 |
|---|---|
| Ghidra | リバースエンジニアリングと逆コンパイル |
| Rizin | バイナリとアセンブリの解析 |
| Cutter | GUI 解析インターフェース |
| JDK 21 | Ghidra に必要な実行環境 |

### 📥 インストール

リポジトリをクローンします。

```bash
git clone https://github.com/YOUR-USERNAME/Reverse-Lab.git
```

プロジェクトフォルダーに移動します。

```bash
cd Reverse-Lab
```

プログラムを実行します。

```bash
python reverse_engine.py
```

**依存関係:** 基本機能では Python の標準ライブラリを使用します。基本的な抽出処理に追加の pip パッケージは必要ありません。

### 🚀 使用方法

**対話型インターフェース:**

```bash
python reverse_engine.py
```

**基本解析:**

```bash
python reverse_engine.py program.exe
```

**Rizin を使用した解析:**

```bash
python reverse_engine.py program.exe --rizin
```

**Ghidra を使用した解析:**

```bash
python reverse_engine.py program.exe --ghidra
```

**すべてのツールを使用した解析:**

```bash
python reverse_engine.py program.exe --tudo
```

**インストール済みツールの確認:**

```bash
python reverse_engine.py --status
```

### 📂 出力フォルダー構成

```text
program_extracted/
│
├── resources/
│   ├── icons/
│   ├── images/
│   ├── html/
│   └── manifest.xml
│
├── embedded/
├── pyinstaller/
├── ghidra/
├── rizin/
└── README.txt
```

出力フォルダーの構成は、実行ファイルの形式や選択したツールによって異なります。

### 🔒 セキュリティ

Reverse Lab は、抽出および解析の処理中に対象プログラムを実行せずにファイルを解析するように設計されています。

また、抽出先のファイルパスに対する保護機能や ZIP ファイルの処理制限も実装されています。

**重要:** 不明な実行ファイルの解析にはリスクが伴う場合があります。隔離された環境を使用し、自分が所有するファイル、オープンソースのファイル、または解析の許可を得たファイルのみを対象にしてください。

### 💻 使用技術

- Python
- PE (Portable Executable)
- PyInstaller
- Ghidra
- Rizin
- Cutter
- Java JDK 21

---

## 🤖 Credits

README documentation created with AI assistance.

**The project was developed by Stock.**

---

<p align="center">
  Made with ❤️ and Python
  <br>
  <b>STOCK © 2026</b>
</p>
