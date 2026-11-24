 <div align="center">

<img src="https://i.pinimg.com/1200x/be/49/5a/be495a9ae2bb6de49ac21e5f83f269b6.jpg" width="100%" alt="Reverse Lab Banner"/>

# REVERSE LAB

**Advanced Executable Analysis & Reverse Engineering Toolkit**

Uma ferramenta em Python para análise de executáveis, extração de recursos e engenharia reversa, reunindo ferramentas poderosas em um único ambiente.

[![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

**Languages / Idiomas / 言語**

🇧🇷 Português (Brasil) · 🇺🇸 English · 🇯🇵 日本語

</div>

---

## Sobre o projeto

O **Reverse Lab** é uma ferramenta desenvolvida em Python com o objetivo de facilitar a análise interna de executáveis e a identificação de tecnologias utilizadas em sua compilação.

O projeto combina extração automatizada de recursos, identificação de arquivos embutidos e integração com ferramentas de engenharia reversa.

Tudo isso através de uma interface interativa diretamente no terminal.

## Funcionalidades

- **PE Resource Extraction** — Extração de recursos internos de executáveis Windows, incluindo ícones, imagens, manifestos e textos.
- **File Carving** — Identificação e extração de arquivos embutidos através de assinaturas binárias.
- **PyInstaller Extraction** — Identificação e extração de pacotes PyInstaller, módulos e arquivos Python compilados.
- **Technology Detection** — Identificação de tecnologias como Python, .NET, Electron, Java, Unity, Go e Rust.
- **Ghidra Integration** — Análise e decompilação de funções para pseudocódigo C.
- **Rizin Integration** — Extração de informações, strings, funções e assembly.
- **Cutter Integration** — Abertura de executáveis em uma interface gráfica de análise.
- **Tool Manager** — Instalação, gerenciamento e remoção de ferramentas externas.
- **Automatic Reports** — Geração de relatórios com informações sobre os arquivos analisados.

## Ferramentas integradas

| Ferramenta | Função |
|---|---|
| Ghidra | Engenharia reversa e decompilação |
| Rizin | Análise de binários e assembly |
| Cutter | Interface gráfica para análise |
| JDK 21 | Ambiente necessário para o Ghidra |

## Instalação

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

## Como utilizar

### Interface interativa

```bash
python reverse_engine.py
```

O menu permite selecionar um executável, escolher ferramentas adicionais e iniciar a análise.

### Linha de comando

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

## Estrutura de saída

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

## Segurança

O Reverse Lab foi desenvolvido para analisar arquivos sem executar o programa analisado durante o processo de extração e análise.

Também possui mecanismos de proteção para caminhos de arquivos extraídos e limites para processamento de arquivos ZIP.

**Importante:** a análise de executáveis desconhecidos ainda pode apresentar riscos. Utilize ambientes isolados e analise somente arquivos próprios, open source ou para os quais você tenha autorização.

## Tecnologias utilizadas

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
