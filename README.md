# Cerberus

Ferramenta de linha de comando para **descoberta horizontal de domínios**: você passa o
domínio de uma empresa e ela procura outros domínios que pertencem à mesma organização
(outras marcas, o mesmo nome em outros TLDs, infraestrutura de e-mail e DNS própria),
além dos subdomínios. Tudo com fontes públicas e passivas, sem scan de portas.

> ⚠️ Use só em domínios que você tem autorização para investigar. Nos exemplos abaixo,
> troque `example.com` pelo domínio que você vai analisar.

## O que ela consulta

- **Certificados TLS** (CertSpotter, e o crt.sh quando você usa `--org`) — nomes que dividem
  certificado com o alvo costumam ser da mesma empresa
- **DNS** — MX, NS, SPF, DMARC e CNAME, além do mesmo nome em outros TLDs
- **Página inicial** — redirecionamentos, links e IDs de Google Analytics / Tag Manager / Pixel
- **WHOIS** — via RDAP, ou pela porta 43 quando o TLD não tem RDAP (ex.: `.me`)
- **Wayback Machine** — hostnames que já existiram

Cada domínio encontrado ganha uma nota de confiança conforme as fontes que o apontaram e é
separado em alvo, subdomínio, relacionado ou terceiros (Google, Cloudflare, redes sociais…).
Se uma fonte cair, as outras continuam.

## Instalação

Precisa do Python 3.11 ou mais novo.

```bash
git clone https://github.com/Retr0Gabriel/cerberus.git
cd cerberus
python -m venv .venv
source .venv/bin/activate        # no Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Uso

```bash
python main.py analyze example.com --no-llm -v
```

Algumas opções que uso bastante:

```bash
python main.py analyze example.com --org "Empresa S.A."          # inclui busca por organização no crt.sh
python main.py analyze example.com -f json -o resultado.json     # saída em JSON
python main.py analyze example.com --collectors dns,whois        # só algumas fontes
python main.py analyze --help                                    # todas as opções
```

### Ver as requisições (estilo Burp)

```bash
python main.py analyze example.com --no-llm --har trafego.har
python main.py traffic trafego.har            # lista tudo
python main.py traffic trafego.har --show 4   # requisição e resposta completas
```

O `.har` também abre no DevTools do Chrome. Se preferir o próprio Burp, aponte
`HTTPS_PROXY=http://127.0.0.1:8080` e `SSL_CERT_FILE` para o certificado do Burp em PEM.

## Revisão por IA (opcional)

A classificação automática pega o grosso, mas sempre sobra ruído (um link pro Instagram, o
mesmo nome registrado por outra pessoa em `.net`…). Dá para passar a lista duvidosa por um
modelo de linguagem, que descarta os falsos positivos e explica cada decisão:

| `--llm` | Custo | Como |
|---|---|---|
| `manual` | grátis | gera um prompt para colar em qualquer chat; a resposta volta com `apply-verdict` |
| `openai` | grátis | modelo local com [Ollama](https://ollama.com) ou qualquer API compatível com OpenAI |
| `claude` | pago | API da Anthropic (`ANTHROPIC_API_KEY`) |
| `nenhum` | grátis | só a classificação automática (`--no-llm`) |

```bash
# modo manual
python main.py analyze example.com --llm manual
python main.py apply-verdict revisao-example.com.relatorio.json resposta.txt

# Ollama
ollama pull qwen2.5:3b
export CERBERUS_LLM_BASE_URL=http://localhost:11434/v1   # Windows: $env:CERBERUS_LLM_BASE_URL="..."
python main.py analyze example.com --llm openai
```

Modelos pequenos erram bastante, então no modo `openai` eles têm limites: não podem
descartar domínios com evidência forte nem mudar muito a nota.

Variáveis (podem ficar num `.env`, veja o `.env.example`): `ANTHROPIC_API_KEY`,
`CERBERUS_MODEL`, `CERBERUS_LLM_BASE_URL`, `CERBERUS_LLM_MODEL`, `CERBERUS_LLM_API_KEY` e
`CERTSPOTTER_API_KEY` (opcional, aumenta o limite do CertSpotter).

## Segurança

Como a ferramenta processa dados que o próprio alvo controla, ela:

- mostra tudo no terminal sem caracteres de controle nem marcação (nada de limpar a tela,
  trocar o título da janela ou criar link falso);
- só acessa endereços públicos — se o alvo redirecionar para `169.254.169.254`, `10.x`,
  `localhost` etc., a requisição é bloqueada.

## Testes offline

```bash
pytest            # as dependências de teste já vêm no requirements.txt
python main.py analyze acmecorp.com.br --no-llm --replay tests/fixtures/acmecorp.json
```

Os testes não acessam a rede. O `--replay` roda a análise inteira a partir de respostas
gravadas; o `acmecorp.json` é um cenário fictício (a empresa não existe).

## Licença

MIT
