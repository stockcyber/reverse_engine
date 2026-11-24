 <div align="center">

<img src="https://i.pinimg.com/1200x/be/49/5a/be495a9ae2bb6de49ac21e5f83f269b6.jpg" width="100%" alt="Reverse Lab Banner"/>

# REVERSE LAB

**Advanced Executable Analysis & Reverse Engineering Toolkit**

Uma ferramenta em Python para análise de executáveis, extração de recursos e engenharia reversa, reunindo ferramentas poderosas em um único ambiente.

[![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

</div>

---

<p align="center">
  <a href="#-português">Português</a> •
  <a href="#-english">English</a> •
  <a href="#-日本語">日本語</a>
</p>

---

## Português

### Sobre o projeto

O **Reverse Lab** é uma ferramenta desenvolvida em Python com o objetivo de facilitar a análise interna de executáveis e a identificação de tecnologias utilizadas em sua compilação.

O projeto combina extração automatizada de recursos, identificação de arquivos embutidos e integração com ferramentas de engenharia reversa.

Tudo isso através de uma interface interativa diretamente no terminal.

### Funcionalidades

- **PE Resource Extraction** — Extração de recursos internos de executáveis Windows, incluindo ícones, imagens, manifestos e textos.
- **File Carving** — Identificação e extração de arquivos embutidos através de assinaturas binárias.
- **PyInstaller Extraction** — Identificação e extração de pacotes PyInstaller, módulos e arquivos Python compilados.
- **Technology Detection** — Identificação de tecnologias como Python, .NET, Electron, Java, Unity, Go e Rust.
- **Ghidra Integration** — Análise e decompilação de funções para pseudocódigo C.
- **Rizin Integration** — Extração de informações, strings, funções e assembly.
- **Cutter Integration** — Abertura de executáveis em uma interface gráfica de análise.
- **Tool Manager** — Instalação, gerenciamento e remoção de ferramentas externas.
- **Automatic Reports** — Geração de relatórios com informações sobre os arquivos analisados.

### Ferramentas integradas

| Ferramenta | Função |
|---|---|
| Ghidra | Engenharia reversa e decompilação |
| Rizin | Análise de binários e assembly |
| Cutter | Interface gráfica para análise |
| JDK 21 | Ambiente necessário para o Ghidra |

### Instalação

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

### Como utilizar

#### Interface interativa

```bash
python reverse_engine.py
```

O menu permite selecionar um executável, escolher ferramentas adicionais e iniciar a análise.

#### Linha de comando

Análise básica:

```bash
python reverse_engine.py programa.exe
```

Análise com Rizin:

```bash
python reverse_engine.py programa.exe --rizin
```

Análise com Ghidra:

```bash
python reverse_engine.py programa.exe --ghidra
```

Análise com todas as ferramentas:

```bash
python reverse_engine.py programa.exe --tudo
```

Verificar ferramentas instaladas:

```bash
python reverse_engine.py --status
```

### Estrutura de saída

Após a análise, os arquivos extraídos são organizados automaticamente:

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

A estrutura varia de acordo com o formato do executável e as ferramentas selecionadas.

### Segurança

O Reverse Lab foi desenvolvido para analisar arquivos sem executar o programa analisado durante o processo de extração e análise.

Também possui mecanismos de proteção para caminhos de arquivos extraídos e limites para processamento de arquivos ZIP.

**Importante:** a análise de executáveis desconhecidos ainda pode apresentar riscos. Utilize ambientes isolados e analise somente arquivos próprios, open source ou para os quais você tenha autorização.

### Tecnologias utilizadas

- Python
- PE (Portable Executable)
- PyInstaller
- Ghidra
- Rizin
- Cutter
- Java JDK 21

---

## English

### About the project

**Reverse Lab** is a Python-based tool designed to simplify executable analysis and identify the technologies used in their compilation.

The project combines automated resource extraction, embedded file identification, and integration with reverse engineering tools.

All of this is available through an interactive terminal interface.

### Features

- **PE Resource Extraction** — Extracts internal resources from Windows executables, including icons, images, manifests, and text.
- **File Carving** — Identifies and extracts embedded files using binary signatures.
- **PyInstaller Extraction** — Identifies and extracts PyInstaller packages, modules, and compiled Python files.
- **Technology Detection** — Identifies technologies such as Python, .NET, Electron, Java, Unity, Go, and Rust.
- **Ghidra Integration** — Analyzes and decompiles functions into C pseudocode.
- **Rizin Integration** — Extracts information, strings, functions, and assembly.
- **Cutter Integration** — Opens executables in a graphical analysis interface.
- **Tool Manager** — Installs, manages, and removes external tools.
- **Automatic Reports** — Generates reports containing information about analyzed files.

### Integrated tools

| Tool | Purpose |
|---|---|
| Ghidra | Reverse engineering and decompilation |
| Rizin | Binary and assembly analysis |
| Cutter | Graphical analysis interface |
| JDK 21 | Required environment for Ghidra |

### Installation

Clone the repository:

```bash
git clone https://github.com/YOUR-USERNAME/Reverse-Lab.git
```

Navigate to the project directory:

```bash
cd Reverse-Lab
```

Run:

```bash
python reverse_engine.py
```

**Dependencies:** the core project uses Python standard libraries. No additional pip packages are required for basic extraction.

### How to use

#### Interactive interface

```bash
python reverse_engine.py
```

The menu allows you to select an executable, choose additional tools, and start the analysis.

#### Command line

Basic analysis:

```bash
python reverse_engine.py program.exe
```

Analysis with Rizin:

```bash
python reverse_engine.py program.exe --rizin
```

Analysis with Ghidra:

```bash
python reverse_engine.py program.exe --ghidra
```

Analysis with all tools:

```bash
python reverse_engine.py program.exe --tudo
```

Check installed tools:

```bash
python reverse_engine.py --status
```

### Output structure

After the analysis, extracted files are automatically organized:

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

The structure varies depending on the executable format and the selected tools.

### Security

Reverse Lab was designed to analyze files without executing the analyzed program during the extraction and analysis process.

It also includes protection mechanisms for extracted file paths and processing limits for ZIP files.

**Important:** analyzing unknown executables may still involve risks. Use isolated environments and only analyze files you own, open-source files, or files you are authorized to inspect.

### Technologies used

- Python
- PE (Portable Executable)
- PyInstaller
- Ghidra
- Rizin
- Cutter
- Java JDK 21

---

## 日本語

### プロジェクトについて

**Reverse Lab** は、実行ファイルの内部解析や、コンパイルに使用された技術の特定を容易にするために Python で開発されたツールです。

リソースの自動抽出、埋め込みファイルの識別、リバースエンジニアリングツールとの連携機能を備えています。

これらすべての機能を、ターミナル上の対話型インターフェースから利用できます。

### 主な機能

- **PE Resource Extraction** — Windows 実行ファイルからアイコン、画像、マニフェスト、テキストなどの内部リソースを抽出します。
- **File Carving** — バイナリシグネチャを使用して埋め込みファイルを識別・抽出します。
- **PyInstaller Extraction** — PyInstaller パッケージ、モジュール、コンパイル済み Python ファイルを識別・抽出します。
- **Technology Detection** — Python、.NET、Electron、Java、Unity、Go、Rust などの技術を識別します。
- **Ghidra Integration** — 関数を解析し、C 言語形式の疑似コードに逆コンパイルします。
- **Rizin Integration** — 情報、文字列、関数、アセンブリを抽出します。
- **Cutter Integration** — 実行ファイルを GUI 解析インターフェースで開きます。
- **Tool Manager** — 外部ツールのインストール、管理、削除を行います。
- **Automatic Reports** — 解析したファイルの情報を含むレポートを自動生成します。

### 統合ツール

| ツール | 機能 |
|---|---|
| Ghidra | リバースエンジニアリングと逆コンパイル |
| Rizin | バイナリとアセンブリの解析 |
| Cutter | GUI 解析インターフェース |
| JDK 21 | Ghidra に必要な実行環境 |

### インストール

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

### 使用方法

#### 対話型インターフェース

```bash
python reverse_engine.py
```

メニューから実行ファイルを選択し、追加ツールを指定して解析を開始できます。

#### コマンドライン

基本解析:

```bash
python reverse_engine.py program.exe
```

Rizin を使用した解析:

```bash
python reverse_engine.py program.exe --rizin
```

Ghidra を使用した解析:

```bash
python reverse_engine.py program.exe --ghidra
```

すべてのツールを使用した解析:

```bash
python reverse_engine.py program.exe --tudo
```

インストール済みツールの確認:

```bash
python reverse_engine.py --status
```

### 出力フォルダー構成

解析後、抽出されたファイルは自動的に整理されます。

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

フォルダー構成は、実行ファイルの形式や選択したツールによって異なります。

### セキュリティ

Reverse Lab は、抽出および解析の処理中に対象プログラムを実行せずにファイルを解析するように設計されています。

また、抽出先のファイルパスに対する保護機能や ZIP ファイルの処理制限も備えています。

**重要:** 不明な実行ファイルの解析にはリスクが伴う場合があります。隔離された環境を使用し、自分が所有するファイル、オープンソースのファイル、または解析の許可を得たファイルのみを対象にしてください。

### 使用技術

- Python
- PE (Portable Executable)
- PyInstaller
- Ghidra
- Rizin
- Cutter
- Java JDK 21

---

## Agradecimentos

- **[Claude (Anthropic)](https://claude.ai/)** — Assistência no desenvolvimento, sugestões técnicas, resolução de problemas e aprimoramento do projeto.

---

<div align="center">

**REVERSE LAB**

*Understand binaries. Explore internals. Learn reverse engineering.*

Developed by **Stock**.

</div>
