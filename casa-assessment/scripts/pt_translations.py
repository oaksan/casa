"""Brazilian Portuguese (PT-BR) technical translations for the 8 domains and 76 controls of ADA CASA 3.0."""

from __future__ import annotations

import re

DOMAINS_PT: dict[str, str] = {
    "Software Composition & Supply Chain": "Composição de Software e Cadeia de Suprimentos",
    "Static Code Analysis & Secrets": "Análise Estática de Código e Segredos",
    "Transport Security": "Segurança de Transporte",
    "Server Configuration & Response Headers": "Configuração de Servidor e Cabeçalhos de Resposta",
    "Authentication & Session Management": "Autenticação e Gerenciamento de Sessão",
    "Authorization & Injection": "Autorização e Injeção",
    "Application Use of OAuth 2.0 / OpenID Connect": "Uso de OAuth 2.0 / OpenID Connect pela Aplicação",
    "Webhook Security": "Segurança de Webhooks",
}

TITLES_PT: dict[str, str] = {
    # Domain 1: SCA
    "SCA-01": "Nenhuma dependência contém vulnerabilidade Crítica/Alta alcançável ou entrada no catálogo CISA KEV",
    "SCA-02": "Nenhum componente está em fim de vida útil (EOL), sem manutenção ou proveniente de repositório não confiável",
    "SCA-03": "Imagens base de contêineres e pacotes do SO não contêm CVEs Críticas/Altas não mitigadas",
    "SCA-04": "Um SBOM completo e legível por máquina é publicado para a build avaliada e corresponde ao SBOM gerado pelo avaliador",
    "SCA-05": "Nenhuma dependência corresponde a um alerta de pacote malicioso conhecido (typosquatting, protestware, mantenedor comprometido)",
    # Domain 2: SAST (AL1 + AL2)
    "SAST-01": "Sem senhas, chaves de API, tokens ou credenciais fixadas (hardcoded) no código-fonte, recursos ou configuração de build",
    "SAST-02": "Sem chaves privadas, certificados ou material de confiança commitados no repositório ou distribuídos nos artefatos",
    "SAST-03": "Sem algoritmos de cifra obsoletos ou quebrados (DES, 3DES, RC4, Blowfish, modo ECB)",
    "SAST-04": "Sem funções de hash fracas (MD5, SHA-1) utilizadas em qualquer contexto relevante para segurança",
    "SAST-05": "Senhas armazenadas usando KDF memory-hard aprovado com salt único por usuário (Argon2id, scrypt, bcrypt, PBKDF2)",
    "SAST-06": "Toda aleatoriedade relevante para segurança utiliza um gerador criptograficamente seguro (CSPRNG)",
    "SAST-07": "Os frameworks protegem contra atribuição em massa (mass assignment) / auto-binding inseguro",
    "SAST-08": "O acesso ao banco de dados utiliza exclusivamente consultas parametrizadas, ORMs ou entrada devidamente escapada",
    "SAST-09": "A desserialização de dados não confiáveis é evitada ou protegida por integridade",
    "SAST-10": "Sem execução dinâmica de código sobre entradas não confiáveis (eval, Function, exec, reflection)",
    "SAST-11": "Caminhos de arquivo não são construídos a partir de metadados não validados fornecidos pelo usuário (Path Traversal)",
    "SAST-12": "Segredos do lado do servidor são mantidos em cofre gerenciado, não em arquivos de configuração ou variáveis embutidas em imagens",
    "SAST-13": "Credenciais, dados de pagamento e tokens nunca são gravados em logs; tokens de sessão aparecem apenas em formato hash irreversível",
    "SAST-14": "Sem backdoors, contas não documentadas, bombas-relógio (time bombs) ou lógica maliciosa",
    # Domain 3: TLS
    "TLS-01": "TLS exigido em todos os endpoints; sem fallback em texto claro; HTTP redireciona para HTTPS",
    "TLS-02": "Apenas TLS 1.2 e TLS 1.3 habilitados; SSLv3, TLS 1.0 e TLS 1.1 rejeitados",
    "TLS-03": "Apenas suítes de cifra fortes; suítes NULL, EXPORT, anônimas, RC4 e CBC legadas rejeitadas; forward secrecy preferido",
    "TLS-04": "A cadeia de certificados é válida, confiável, não expirada e corresponde ao hostname",
    "TLS-05": "Cabeçalho Strict-Transport-Security (HSTS) presente com max-age ≥ 31536000",
    "TLS-06": "Sem vulnerabilidades conhecidas de implementação TLS (Heartbleed, ROBOT, renegociação insegura, CRIME)",
    # Domain 4: CFG
    "CFG-01": "Listagem de diretórios desabilitada; enumeração de arquivos e diretórios não é possível",
    "CFG-02": "Modos de depuração (debug) do framework e do servidor desabilitados em produção",
    "CFG-03": "Sem exposição detalhada de versão ou stack nos cabeçalhos ou corpos de resposta",
    "CFG-04": "Content-Security-Policy (CSP) aplicado; script-src exclui unsafe-inline e unsafe-eval",
    "CFG-05": "Prevenção contra Clickjacking via frame-ancestors ou X-Frame-Options",
    "CFG-06": "Cabeçalho X-Content-Type-Options: nosniff presente em todas as respostas",
    "CFG-07": "Cabeçalhos anti-cache presentes em todas as respostas autenticadas e sensíveis",
    "CFG-08": "CORS utiliza lista de permissão estrita; sem curinga (*) com credenciais; sem reflexão de origem não validada",
    "CFG-09": "Respostas 4xx/5xx retornam mensagens genéricas; sem stack traces, caminhos internos ou detalhes de roteamento",
    "CFG-10": "Nenhuma interface administrativa acessível sem autenticação",
    "CFG-11": "Nenhum registro DNS pendente (dangling DNS) em qualquer host declarado ou cadeia CNAME permite subdomain takeover",
    # Domain 5: AUT (AL1 + AL2)
    "AUT-01": "Nenhuma credencial padrão, compartilhada ou fornecida pelo fabricante é aceita",
    "AUT-02": "Tokens de sessão possuem ≥ 64 bits de entropia",
    "AUT-03": "Um novo token de sessão é emitido após a autenticação (prevenção de fixação de sessão)",
    "AUT-04": "Tokens de sessão e credenciais nunca aparecem em URLs, query strings ou cabeçalho Referer",
    "AUT-05": "O logout invalida a sessão no lado do servidor, incluindo refresh tokens",
    "AUT-06": "Cookies de sessão definem os atributos Secure, HttpOnly e SameSite (Lax ou Strict)",
    "AUT-07": "Tokens stateless são assinados com algoritmo forte; alg:none, confusão de algoritmo e substituição de chave são rejeitados; expiração ≤ 24h",
    "AUT-08": "O armazenamento no cliente (localStorage/sessionStorage) não retém dados sensíveis ou material de autenticação e é limpo no logout",
    "AUT-09": "Proteção anti-automação nos endpoints de autenticação — no máximo 100 tentativas falhas por conta por hora, ou CAPTCHA / MFA / bloqueio temporário",
    "AUT-10": "Timeout de inatividade de sessão imposto; reautenticação exigida após o período de inatividade",
    "AUT-11": "Alteração ou redefinição de senha encerra outras sessões ativas; códigos out-of-band de uso único (≤ 10 min) e links de reset (≤ 60 min) gerados via CSPRNG (≥ 20 bits)",
    "AUT-12": "Interfaces administrativas exigem autenticação multifator (MFA): apenas a senha correta não concede acesso a funções ou dados administrativos",
    # Domain 6: AZI (AL1 + AL2)
    "AZI-01": "Mecanismo forte anti-CSRF em todas as funcionalidades autenticadas que alteram estado",
    "AZI-02": "Sem Cross-Site Scripting (XSS) — refletido, armazenado ou baseado em DOM",
    "AZI-03": "Sem injeção de SQL ou NoSQL",
    "AZI-04": "Sem injeção de comandos do sistema operacional (OS Command Injection)",
    "AZI-05": "Sem inclusão de arquivos locais/remotos (LFI/RFI) ou travessia de diretórios (Path Traversal)",
    "AZI-06": "Sem redirecionamento aberto (Open Redirect) ou encaminhamento não validado; poluição de parâmetros HTTP (HPP) tratada com segurança",
    "AZI-07": "Controle de acesso imposto em camada confiável no lado do servidor, e não no cliente",
    "AZI-08": "Sem Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization (BOLA), incluindo acesso entre locatários (cross-tenant)",
    "AZI-09": "Sem escalonamento de privilégios horizontal ou vertical; autorização em nível de função imposta",
    "AZI-10": "Atributos de controle de acesso não são manipuláveis pelo usuário; controle de acesso falha de forma segura (fail-closed) em exceções",
    "AZI-11": "Prevenção contra Server-Side Request Forgery (SSRF) em todas as funcionalidades que buscam URLs",
    "AZI-12": "Sem Server-Side Template Injection (SSTI), injeção de XPath/XML ou XXE",
    "AZI-13": "Uploads de arquivos restritos aos tipos esperados, armazenados fora da raiz web com privilégio mínimo e nunca executáveis diretamente",
    # Domain 7: OAU (AL1 + AL2)
    "OAU-01": "Apenas o fluxo Authorization Code é utilizado — fluxos Implicit e Resource Owner Password Credentials (ROPC) são proibidos",
    "OAU-02": "PKCE com S256 é exigido em todos os fluxos de código de autorização, públicos e confidenciais",
    "OAU-03": "A aplicação registra apenas URIs de redirecionamento exatas (sem curingas), e seu próprio endpoint de callback não contém Open Redirect",
    "OAU-04": "Parâmetros state e nonce OIDC são gerados via CSPRNG, vinculados à sessão do user-agent e validados no retorno",
    "OAU-05": "Clientes nativos, móveis e desktop realizam autorização no navegador do sistema (Custom Tabs / ASWebAuthenticationSession) — nunca em WebView embutida",
    "OAU-06": "Nenhum client secret está embutido em binário de cliente público, bundle ou pacote de extensão",
    "OAU-07": "Access e refresh tokens são mantidos em armazenamento seguro da plataforma (Keystore, Keychain ou cookie HttpOnly Secure); nunca em localStorage",
    "OAU-08": "Access tokens são transmitidos apenas no cabeçalho Authorization; nunca em query strings ou fragmentos de URL",
    "OAU-09": "Quando o backend aceita ID tokens ou access tokens do provedor de identidade, valida assinatura, iss, aud, exp e scope contra as chaves públicas; rejeita alg:none e confusão de algoritmo",
    "OAU-10": "A aplicação trata refresh tokens corretamente: tokens substituídos são descartados na rotação, nunca duplicados entre armazenamentos, e falhas não disparam reautorização silenciosa",
    "OAU-11": "Tokens são revogados no logout do usuário, na revogação iniciada pelo usuário e na exclusão da conta",
    # Domain 8: WHK (AL1 + AL2)
    "WHK-01": "O tráfego de webhooks é entregue exclusivamente sobre HTTPS com TLS 1.2+; endpoints em texto claro são recusados",
    "WHK-02": "Payloads de webhook são autenticados com assinatura criptográfica HMAC-SHA256 (ou superior) e verificados em tempo constante",
    "WHK-03": "URLs de callback de webhook fornecidas pelo usuário impedem SSRF contra endereços internos/metadados; segredos de assinatura não estão fixados no código",
    "WHK-04": "Proteção contra replay via timestamps assinados com janela de aceitação limitada e tratamento de idempotência",
}

PHRASE_REPLACEMENTS: list[tuple[str, str]] = [
    ("Evidence collected:", "Evidência coletada:"),
    ("Verified PASS criterion:", "Critério de PASS verificado:"),
    ("Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.", "Produzido pelo laboratório/avaliador. Saídas de scan ou atestações fornecidas pelo desenvolvedor não são aceitas."),
    ("Assessor-generated SBOM (CycloneDX 1.5+ or SPDX 2.3+) and vulnerability findings in SARIF 2.1.0.", "SBOM gerado pelo avaliador (CycloneDX 1.5+ ou SPDX 2.3+) e achados de vulnerabilidade em SARIF 2.1.0."),
    ("Static-analysis and secret-scan findings in SARIF 2.1.0, with rule identifiers and file locations.", "Achados de análise estática e varredura de segredos em SARIF 2.1.0, com identificadores de regra e localização nos arquivos."),
    ("Harness and DAST findings in SARIF 2.1.0 and a redacted HAR 1.2 capture of the replayed requests.", "Achados do harness e DAST em SARIF 2.1.0 e captura HAR 1.2 redigida das requisições reproduzidas."),
    ("Authenticated DAST and harness findings in SARIF 2.1.0 and a redacted HAR 1.2 capture.", "Achados de DAST autenticado e harness em SARIF 2.1.0 e captura HAR 1.2 redigida."),
    ("Redacted HAR 1.2 capture of the authorization flow; SARIF 2.1.0 where a client artifact is analysed statically.", "Captura HAR 1.2 redigida do fluxo de autorização; SARIF 2.1.0 quando artefatos clientes são analisados estaticamente."),
    ("Zero findings whose CVSS v3.1 base ≥ 7.0", "Zero achados com CVSS v3.1 base ≥ 7.0"),
    ("Zero findings", "Zero achados"),
    ("≥ 1 finding", "≥ 1 achado"),
    ("Lab adjudication of the tool output decides the verdict.", "A adjudicação do laboratório sobre a saída da ferramenta decide o veredito."),
]


def translate_text_pt(text: str) -> str:
    if not text:
        return ""
    out = text
    for en_str, pt_str in PHRASE_REPLACEMENTS:
        out = out.replace(en_str, pt_str)
    return out
