# Engenharia de Detecção e Simulação de Brute Force (SSH) no Wazuh SIEM

## 📋 Descrição do Projeto
[span_2](start_span)Este projeto documenta a implementação prática de um ambiente de segurança defensiva em arquitetura de Sandbox[span_2](end_span). [span_3](start_span)O objetivo principal consiste na simulação assistida de ataques de força bruta contra o protocolo de autenticação remota SSH e na posterior validação da telemetria, modelagem e eficácia de regras analíticas customizadas de detecção utilizando a plataforma Wazuh SIEM[span_3](end_span).

[span_4](start_span)[span_5](start_span)O escopo técnico abrange desde a fase inicial de reconhecimento e mapeamento da superfície de ataque até o desenvolvimento de assinaturas em formato estruturado (XML) e a proposição de controles de mitigação severa (*hardening*) de ativos[span_4](end_span)[span_5](end_span).

---

## 🏗️ Arquitetura e Ambiente de Testes
[span_6](start_span)O laboratório foi provisionado em ambiente virtual isolado, composto pelos seguintes ativos e segmentações de rede[span_6](end_span):

* **[span_7](start_span)[span_8](start_span)Ativo Atacante:** Instância executando Kali Linux voltada para auditoria de segurança ofensiva[span_7](end_span)[span_8](end_span).
* **[span_9](start_span)Ativo Vítima:** Servidor executando Ubuntu Server 24.04 LTS (IP: `10.0.0.62`), monitorado nativamente pelo Wazuh Agent v4.7.5[span_9](end_span).
* **[span_10](start_span)[span_11](start_span)Servidor Centralizador (SIEM):** Instância dedicada ao Wazuh Manager (IP: `10.0.0.59`), responsável pelas regras analíticas, decodificação de payloads e centralização gráfica dos eventos de segurança[span_10](end_span)[span_11](end_span).

---

## 🛡️ Alinhamento Estrutural com o Framework NIST (CSF v2.0)
[span_12](start_span)A abordagem operacional e metodológica seguiu estritamente as funções centrais propostas pelo NIST Cybersecurity Framework[span_12](end_span):

### 1. Identificar (Identify)
* **[span_13](start_span)Superfície Exposta:** Identificação de falha crítica de segurança caracterizada pela presença de credenciais administrativas fracas associadas à total ausência de mecanismos locais de *rate limiting* ou bloqueio preventivo de tráfego de rede no daemon do SSH[span_13](end_span).

### 2. Proteger (Protect)
* **[span_14](start_span)Gestão de Identidade:** Planejamento e validação de políticas rígidas de senhas de alta entropia e restrição de acesso direto ao usuário de privilégios máximos (*root*) via SSH[span_14](end_span).
* **[span_15](start_span)Segurança de Rede:** Implementação de regras restritivas através do firewall local (UFW/iptables), delimitando a porta TCP 22 a subredes administrativas[span_15](end_span).
* **[span_16](start_span)[span_17](start_span)Taxonomia e Vinculação:** Associação prévia de gatilhos do SIEM às táticas e sub-técnicas documentadas na base de conhecimento global MITRE ATT&CK[span_16](end_span)[span_17](end_span).

### 3. Detectar (Detect)
* **[span_18](start_span)Centralização Contínua:** Configuração do módulo nativo `logcollector` do agente Wazuh focado no monitoramento e ingestão em tempo real das mensagens geradas pelo arquivo `/var/log/auth.log`[span_18](end_span).
* **[span_19](start_span)Engenharia de Assinaturas:** Desenvolvimento de lógica booleana local para agrupamento e correlação de falhas repetitivas de login originadas de um mesmo vetor de rede de origem[span_19](end_span).

### 4. Responder (Respond)
* **[span_20](start_span)Auditoria de Parser:** Validação sintática minuciosa das estruturas XML concebidas para mitigar falhas de processamento ou parada do motor analítico principal[span_20](end_span).
* **[span_21](start_span)Contenção e Aplicação:** Execução controlada das rotinas de reinicialização do ciclo de vida do `wazuh-manager` para a correta propagação das novas assinaturas sem perdas de telemetria ativa[span_21](end_span).

### 5. Recuperar (Recover)
* **[span_22](start_span)Sanitização Operacional:** Rotacionamento imediato de chaves e senhas utilizadas de maneira temporária na fase ofensiva[span_22](end_span).
* **[span_23](start_span)[span_24](start_span)Melhoria Contínua:** Modelagem futura de playbooks automatizados com o módulo *Active Response* do Wazuh para banimento dinâmico de IPs maliciosos diretamente na camada de rede (firewall) do host impactado[span_23](end_span)[span_24](end_span).

---

## 💻 Engenharia de Detecção: Regras Customizadas (XML)
[span_25](start_span)Para refinar o ecossistema de monitoramento, o arquivo de assinaturas locais `/var/log/ossec/local_rules.xml` foi editado com novas regras analíticas dedicadas[span_25](end_span):

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