# webOS Mega Repository

Catálogo comunitário de aplicativos Homebrew para TVs LG, com foco em webOS 25 e instalação via Developer Mode, sem root.

## 1. Instalação — link para o Homebrew Channel

**Copie este endereço para adicionar o catálogo geral à TV:**

```text
https://raw.githubusercontent.com/thankaniko/webos-mega-repository/main/apps.json
```

[ABRIR FEED DO MEGA REPO](https://raw.githubusercontent.com/thankaniko/webos-mega-repository/main/apps.json)

1. Ative o Developer Mode e instale o Homebrew Channel, se ainda não estiver instalado.
2. Abra o Homebrew Channel na TV e acesse a gestão de repositórios.
3. Adicione a URL completa acima e atualize o catálogo.
4. Confira os requisitos do aplicativo antes de instalar.

Mantenha o Developer Mode válido. Não é necessário conceder root para adicionar o feed.

## 2. BX UT80 Local — catálogo separado

O BX possui código-fonte e ciclo de desenvolvimento independentes no [repositório BX UT80 Local](https://github.com/thankaniko/-bx-ut80-local). Seu feed de distribuição está hospedado em outra branch deste Mega Repo:

```text
https://raw.githubusercontent.com/thankaniko/webos-mega-repository/bx-ut80-local-feed/bx-ut80-local/apps.json
```

[ABRIR FEED DO BX](https://raw.githubusercontent.com/thankaniko/webos-mega-repository/bx-ut80-local-feed/bx-ut80-local/apps.json)

O BX não integra atualmente o catálogo geral. Para acessar ambos, adicione os dois feeds. Não adicione as branches de desenvolvimento do BX como repositórios Homebrew.

## 3. Compatibilidade e critérios

- Prioridade: LG webOS 25 e aplicativos utilizáveis sem root.
- Novas entradas estáveis e atualizações: exigência de evidência de origem, versão, requisitos, integridade SHA-256 e estrutura interna do IPK.
- Pacotes experimentais, requisitos de root indefinidos, divergências de identificador e downloads inválidos exigem revisão; não devem ser promovidos sem evidência adequada.
- A auditoria estática de um pacote não comprova sua instalação, execução, desempenho ou compatibilidade em uma TV física específica.
- Entradas legadas podem ter ressalvas; o catálogo existente não é uma certificação de todos os aplicativos. Observe as restrições de modelo, arquitetura, armazenamento e versão do webOS.
- Os aplicativos pertencem aos respectivos autores. Este catálogo não é afiliado à LG e não concede direitos sobre software de terceiros.

## 4. Estrutura do projeto

| Arquivo | Função |
| --- | --- |
| [apps.json](apps.json) | Catálogo distribuído ao Homebrew Channel |
| [sources.json](sources.json) | Lista de feeds de origem |
| [scripts/audit.py](scripts/audit.py) | Auditoria de fontes, metadados e IPKs |
| [.github/workflows/audit.yml](.github/workflows/audit.yml) | Execução automatizada da auditoria |

## 5. Auditoria e manutenção contínua

O workflow [Audit webOS catalog](../../actions/workflows/audit.yml) executa diariamente, por disparo manual e após mudanças relevantes em seus arquivos de configuração. Ele verifica candidatos e gera relatórios de evidência sem executar os IPKs nem sobrescrever automaticamente o catálogo de produção.

Artefatos da auditoria:

- `report.json`: evidências, rejeições e alertas.
- `candidates.json`: candidatos aprovados na verificação estática.
- `proposed-apps.json`: proposta de atualização do catálogo.
- `pending-downloads.json`: candidatos ainda não verificados.
- `xbox-review.json`: investigação específica de clientes Xbox, pendente de revisão.

A manutenção deve preservar IDs, versões válidas, fontes legítimas, hashes e entradas existentes em caso de falhas transitórias. Mudanças relevantes devem ser revisadas e registradas com evidências antes de promoção. Novas fontes devem ser avaliadas quanto à compatibilidade do formato, origem e segurança. Não publicar pacotes apenas porque o link responde.

## 6. Suporte e contribuição

Ao reportar problemas, informe o modelo da TV, a versão do webOS, o ID e a versão do aplicativo, a URL da fonte e o erro observado. Não compartilhe senhas, chaves privadas, tokens ou dados pessoais.

Consulte as licenças dos projetos upstream e a [licença deste repositório](LICENSE).
