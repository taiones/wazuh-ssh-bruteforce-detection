# Engenharia de Detecção e Simulação de Brute Force (SSH) no Wazuh SIEM

## 📋 Descrição do Projeto
Este projeto documenta a implementação prática de um ambiente de segurança defensiva em arquitetura de Sandbox. O objetivo principal consiste na simulação assistida de ataques de força bruta contra o protocolo de autenticação remota SSH e na posterior validação da telemetria, modelagem e eficácia de regras analíticas customizadas de detecção utilizando a plataforma Wazuh SIEM.

O escopo técnico abrange desde a fase inicial de reconhecimento e mapeamento da superfície de ataque até o desenvolvimento de assinaturas em formato estruturado (XML) e a proposição de controles de mitigação severa (*hardening*) de ativos.

---

## 🏗️ Arquitetura e Ambiente de Testes
O laboratório foi provisionado em ambiente virtual isolado, composto pelos seguintes ativos e segmentações de rede:

* **Ativo Atacante:** Instância executando Kali Linux voltada para auditoria de segurança ofensiva.
* **Ativo Vítima:** Servidor executando Ubuntu Server 24.04 LTS (IP: `10.0.0.62`), monitorado nativamente pelo Wazuh Agent v4.7.5.
* **Servidor Centralizador (SIEM):** Instância dedicada ao Wazuh Manager (IP: `10.0.0.59`), responsável pelas regras analíticas, decodificação de payloads e centralização gráfica dos eventos de segurança.

---

## 🛡️ Alinhamento Estrutural com o Framework NIST (CSF v2.0)
A abordagem operacional e metodológica seguiu estritamente as funções centrais propostas pelo NIST Cybersecurity Framework:

### 1. Identificar (Identify)
* **Superfície Exposta:** Identificação de falha crítica de segurança caracterizada pela presença de credenciais administrativas fracas associadas à total ausência de mecanismos locais de *rate limiting* ou bloqueio preventivo de tráfego de rede no daemon do SSH.

### 2. Proteger (Protect)
* **Gestão de Identidade:** Planejamento e validação de políticas rígidas de senhas de alta entropia e restrição de acesso direto ao usuário de privilégios máximos (*root*) via SSH.
* **Segurança de Rede:** Implementação de regras restritivas através do firewall local (UFW/iptables), delimitando a porta TCP 22 a subredes administrativas.
* **Taxonomia e Vinculação:** Associação prévia de gatilhos do SIEM às táticas e sub-técnicas documentadas na base de conhecimento global MITRE ATT&CK.

### 3. Detectar (Detect)
* **Centralização Contínua:** Configuração do módulo nativo `logcollector` do agente Wazuh focado no monitoramento e ingestão em tempo real das mensagens geradas pelo arquivo `/var/log/auth.log`.
* **Engenharia de Assinaturas:** Desenvolvimento de lógica booleana local para agrupamento e correlação de falhas repetitivas de login originadas de um mesmo vetor de rede de origem.

### 4. Responder (Respond)
* **Auditoria de Parser:** Validação sintática minuciosa das estruturas XML concebidas para mitigar falhas de processamento ou parada do motor analítico principal.
* **Contenção e Aplicação:** Execução controlada das rotinas de reinicialização do ciclo de vida do `wazuh-manager` para a correta propagação das novas assinaturas sem perdas de telemetria ativa.

### 5. Recuperar (Recover)
* **Sanitização Operacional:** Rotacionamento imediato de chaves e senhas utilizadas de maneira temporária na fase ofensiva.
* **Melhoria Contínua:** Modelagem futura de playbooks automatizados com o módulo *Active Response* do Wazuh para banimento dinâmico de IPs maliciosos diretamente na camada de rede (firewall) do host impactado.

---

## 💻 Engenharia de Detecção: Regras Customizadas (XML)
Para refinar o ecossistema de monitoramento, o arquivo de assinaturas locais `/var/log/ossec/local_rules.xml` foi editado com novas regras analíticas dedicadas:

```xml
<group name="syslog,sshd,">

  <rule id="108881" level="5">
    <if_sid>5716</if_sid>
    <srcip>1.1.1.1</srcip>
    <description>sshd: authentication failed from IP 1.1.1.1.</description>
    <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>

  <rule id="100818" level="10">
    <program_name>sshd</program_name>
    <match>error: maximum authentication attempts</match>
    <description>SSH brute force detected: too many failed attempts</description>
    <group>ssh_bruteforce,authentication_failed,</group>
  </rule>

</group>

```
---

## 💡 Nota de Engenharia: A regra customizada herda as propriedades lógicas do parser nativo do serviço e eleva o nível de severidade para 10 (Alta Criticidade), assegurando a correlação gráfica imediata com os requisitos de conformidade regulatória PCI DSS 10.2.4 e 10.2.5 na interface web do SIEM.

## 🚀 Execução do Ataque e Evidências Técnicas
### 1. Varredura de Infraestrutura (Nmap)
A atividade ofensiva iniciou-se através de um mapeamento lógico da rede interna para delimitar portas abertas e serviços vulneráveis expostos.

```bash
nmap -A -v 10.0.0.62
```
O utilitário confirmou a presença do serviço SSH ativo respondendo na porta padrão TCP 22.

### 2. Campanha de Força Bruta (Hydra)
Utilizou-se a ferramenta Hydra, parametrizada de forma paralela e cadenciada, consumindo uma wordlist massiva customizada contra a instância Ubuntu.

```bash
hydra -t 2 -l kali -P /home/kali/minha_worldlist.txt ssh://10.0.0.62
```
### 3. Análise Forense de Logs (/var/log/auth.log)
A volumetria agressiva gerou um rastro claro e padronizado de erros repetitivos no subsistema de autenticação Linux, evidenciando o estouro do limite máximo de tentativas configuradas.

```plaintext
2026-05-17T03:32:29.991261-03:00 kali-VMware-Virtual-Platform sshd-session[5974]: error: maximum authentication attempts exceeded for kali from 10.0.0.57 port 48436 ssh2 [preauth]
2026-05-17T03:32:29.991835-03:00 kali-VMware-Virtual-Platform sshd-session[5974]: Disconnecting authenticating user kali 10.0.0.57 port 48436: Too many authentication failures [preauth]
```
### 4. Triagem e Ingestão de Telemetria no Dashboard do Wazuh
O motor analítico central processou as cadeias de mensagens em tempo de milissegundos, gerando alertas agregados no painel web que correlacionam de forma clara as táticas do MITRE ATT&CK de Acesso a Credenciais (T1110) e Movimentação Lateral (T1021.004).

## 🔒 Conclusões e Recomendações de Hardening
Os testes empíricos evidenciaram que a utilização de configurações padrão de fábrica de serviços expostos eleva de forma severa a superfície de risco dos ativos. Diante do cenário mapeado, recomenda-se a aplicação das seguintes ações imediatas de proteção em ambiente de produção:

Alteração da Porta Padrão do Serviço: Migração da porta padrão TCP 22 do protocolo SSH para uma porta alta aleatória, mitigando as atividades de varreduras automatizadas e robôs baseados em internet pública.

Autenticação Exclusiva por Chaves Públicas: Desativação mandatória da autenticação baseada puramente em senhas textuais em favor de chaves criptográficas fortes de alta robustez (padrões mínimos exigidos: ED25519 ou RSA de 4096 bits).

Mecanismo de Resposta Ativa Remota: Implantação e integração de ferramentas dinâmicas de filtragem como o Fail2ban ou playbooks dedicados de Active Response direto no agente do Wazuh para o banimento definitivo e automatizado de sub-redes ou endereços IPs que excedam 3 erros repetitivos de autenticação.

