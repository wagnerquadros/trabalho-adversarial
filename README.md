# Análise de um Sistema Adversarial

### Um atacante manipula o que o detector lê para não ser alertado; o defensor observa os erros e endurece o contexto; os dois se adaptam rodada a rodada

## Glossário

| Termo                       | Significado neste trabalho                                                                                                                   |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Registro de conexão (fluxo) | Linha do NSL-KDD que descreve uma conexão de rede por 41 atributos, como protocolo, `service` e bytes. É o que o detector julga.             |
| Contexto                    | Tudo o que acompanha o registro na entrada do detector: instruções, descrições dos atributos, exemplos rotulados e forma de apresentação.    |
| Instruções                  | Texto que explica a tarefa ao detector. É a única parte do contexto que o defensor pode revisar.                                             |
| Nota                        | Texto que o atacante anexa ao valor do campo `service` para tentar influenciar o veredito.                                                   |
| Exemplo rotulado            | Registro de referência com a categoria correta, mostrado ao detector como modelo.                                                            |
| `p_attack`                  | Probabilidade de ataque devolvida pelo detector, entre 0 e 1.                                                                                |
| Limiar                      | Valor de corte de `p_attack`: 0,5. A partir dele, o registro gera alerta.                                                                    |
| Veredito                    | Resultado final de um registro: alerta ou sem alerta.                                                                                        |
| Falso alarme                | Alerta emitido sobre um registro legítimo.                                                                                                   |
| F1                          | Medida de desempenho que combina precisão (alertas corretos entre todos os alertas) e revocação (ataques detectados entre todos os ataques). |
| Evasão                      | Registro malicioso que recebe o veredito sem alerta.                                                                                         |
| Sonda                       | Tentativa que o atacante envia para observar o veredito e aprender como o detector reage.                                                    |
| Rodada                      | Um ciclo de ação, resposta, observação e adaptação entre atacante e defensor.                                                                |
| Payoff                      | Número que representa a preferência de um jogador por um resultado do jogo.                                                                  |
| Melhor resposta             | Ação que dá ao jogador o maior payoff diante de uma escolha fixa do outro jogador.                                                           |
| Equilíbrio de Nash          | Combinação de ações em que nenhum jogador melhora mudando sozinho.                                                                           |
| Estratégia mista            | Escolha de ações por sorteio, com probabilidades definidas.                                                                                  |
| Insider                     | Pessoa com acesso interno a componentes, como exemplos ou arquivos de instruções.                                                            |
| Oráculo                     | Fonte que revela ao atacante uma medida que ele não teria na prática, como o F1 da avaliação.                                                |
| Fail-open                   | Política em que uma falha de processamento é tratada como "sem alerta".                                                                      |

## 1. Proposta

Um atacante simulado modifica o texto apresentado ao Jev para tentar evitar a detecção; o defensor observa os erros e revisa as instruções. Ambos adaptam suas escolhas a partir das respostas que podem observar.

O trabalho analisa uma interação específica: a classificação de um registro de conexão pelo Jev IDS, utilizando dados do NSL-KDD. O atacante busca fazer registros maliciosos serem classificados como normais, inserindo notas enganosas em um campo do registro. O defensor procura reconhecer esses ataques sem aumentar excessivamente os falsos alarmes sobre tráfego legítimo.

Para delimitar o estudo, o atacante poderá alterar somente a nota textual e observar se suas próprias tentativas geraram alerta. O defensor poderá revisar somente as instruções que orientam o Jev. Os exemplos de referência e as demais configurações permanecerão fixos, permitindo comparar os efeitos dessas escolhas.

O projeto **Jev IDS** será a base conceitual e experimental. Por questões de custo, adotaremos duas alternativas de execução local ao modelo Jev: **Qwen3:8b, por meio do Ollama**, e **Laya multilingual**. Cada modelo será considerado separadamente na mesma função de detector.

A pergunta central será:

> **Como a revisão das instruções pelo defensor influencia a detecção quando o atacante adapta suas notas a partir dos resultados observados, e como essa interação se manifesta no Qwen e no Laya?**

Esta proposta apresenta a ideia, os participantes e o recorte da análise. O foco será compreender o conflito de interesses e o ciclo de adaptação entre atacante e defensor.

## 2. Sistema e interação analisada

### Projeto de referência e escolha das tecnologias

O sistema escolhido é o Jev IDS, apresentado no projeto [Jev-ids-adversarial](https://github.com/Tucelos/Jev-ids-adversarial). Ele utiliza o Jev para classificar registros de conexões de rede e permite investigar como mudanças no contexto apresentado ao detector influenciam suas decisões.

O Jev é um modelo de inteligência artificial da TypeSafe, descrito como um System One Model. Ele recebe informações e perguntas com formatos de resposta definidos, retornando decisões estruturadas, como a escolha de uma categoria ou uma probabilidade. Essas respostas podem ser utilizadas diretamente por um programa. [Documentação oficial do Jev](https://docs.typesafe.ai/introduction).

No Jev IDS, cada avaliação reúne um registro de conexão, instruções sobre a tarefa e exemplos rotulados de referência. O Jev responde a duas perguntas: se a conexão representa um ataque e a qual categoria ela pertence. A probabilidade de ataque, denominada `p_attack`, é utilizada para produzir o veredito: valores iguais ou superiores a 0,5 geram alerta.

O acesso ao Jev ocorre por API, com cobrança por consumo de tokens de entrada. Para viabilizar a exploração de diferentes contextos sem despesas com essa API, optamos pelos modelos locais descritos a seguir.

| Tecnologia            | O que é                                                                                                                                                                                                 | Papel na proposta                                                                                                                                                                                                  |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Qwen3:8b**          | Modelo de linguagem da família Qwen, com cerca de oito bilhões de parâmetros, capaz de interpretar instruções e gerar respostas textuais.                                                               | Será solicitado a classificar cada registro e responder em formato estruturado. Será utilizado com o modo _thinking_ desativado. [Documentação do Qwen](https://huggingface.co/Qwen/Qwen3-8B).                     |
| **Ollama**            | Software que permite executar modelos de IA no computador e acessá-los por uma interface de programação.                                                                                                | Executará o Qwen localmente e fará a comunicação entre ele e o projeto. O modelo avaliado será o Qwen; Ollama será o ambiente de execução. [Documentação do Ollama](https://docs.ollama.com/).                     |
| **Laya multilingual** | Modelo de decisão da Convai Innovations, com pesos abertos, voltado a responder perguntas estruturadas sobre informações fornecidas. Integra a família Laya, apresentada como uma abordagem _System 1_. | Será a segunda alternativa de classificador local, retornando probabilidades e categorias em um formato compatível com a integração do Jev. [Documentação do Laya](https://huggingface.co/convaiinnovations/laya). |

Essa escolha permite utilizar os recursos computacionais disponíveis ao grupo, sem cobrança de um provedor por cada inferência local. Permanecem os custos de processamento, memória e energia. O Jev IDS continuará sendo a referência do trabalho, enquanto as decisões analisadas serão produzidas pelo Qwen e pelo Laya, modelos distintos do Jev.

O estudo utiliza o NSL-KDD, um conjunto de dados com registros de conexões descritos por 41 atributos, como protocolo, serviço, duração e quantidade de bytes. Ele foi derivado do KDD'99 com a remoção de registros duplicados ([Tavallaee et al., 2009](https://doi.org/10.1109/CISDA.2009.5356528); [CIC/UNB](https://www.unb.ca/cic/datasets/nsl.html)). A categoria verdadeira de cada registro avaliado fica reservada à verificação dos resultados e não é apresentada ao detector.

### O que significa alterar o contexto

Contexto é a informação que orienta a interpretação do registro, incluindo instruções, descrições dos atributos e das categorias, exemplos de referência e a apresentação dos dados. Alterar essas informações pode mudar a decisão do Jev sem retreinar o modelo.

Neste trabalho, serão exploradas duas alterações: o atacante poderá inserir uma nota enganosa no campo `service`, enquanto o defensor poderá revisar as instruções da tarefa. Os demais elementos permanecerão fixos. O risco investigado é que uma mensagem inserida como dado seja interpretada pelo detector como uma orientação confiável. Esse risco é conhecido como injeção indireta de prompt: conteúdo externo, ao ser lido pelo modelo, altera seu comportamento de forma não pretendida ([OWASP, 2025](https://genai.owasp.org/llmrisk/llm01-prompt-injection/); [Greshake et al., 2023](https://doi.org/10.48550/arXiv.2302.12173)).

A interação ocorrerá em uma simulação com registros do dataset, sem envio de ataques a uma rede real. O atacante receberá apenas o veredito de suas próprias tentativas; o defensor receberá os resultados autorizados da avaliação para orientar suas revisões. A análise buscará compreender como essas escolhas afetam a detecção de ataques e os falsos alarmes sobre registros legítimos.

## 3. Desenvolvimento

A análise considera dois participantes estratégicos: um atacante simulado e um defensor. O atacante modifica notas inseridas nos registros para tentar evitar alertas; o defensor revisa as instruções para melhorar a detecção sem aumentar excessivamente os falsos alarmes. O Jev realiza a classificação, enquanto o ambiente experimental organiza as avaliações e controla as informações entregues a cada participante.

## 3.1 Descrição do sistema adversarial

### Atores

| Ator              | Objetivo                                                                          | Ações ou capacidades                                                                  | Informações observáveis                                                                                                                                                     | Restrições ou custos                                                                                                                                                                                                   |
| ----------------- | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Atacante simulado | Fazer registros maliciosos receberem o veredito sem alerta.                       | Escolher, manter, retirar ou reformular uma nota textual inserida no campo `service`. | Suas próprias notas e os vereditos das próprias tentativas: alerta ou sem alerta.                                                                                           | Não acessa as instruções do defensor, os exemplos, o gabarito ou as métricas de avaliação. Não altera outros atributos. Está sujeito a limites de tentativas e de tamanho da nota.                                     |
| Defensor          | Detectar registros maliciosos e limitar os falsos alarmes sobre tráfego legítimo. | Escolher, manter ou revisar as instruções apresentadas ao Jev.                        | Suas instruções, as notas testadas e os resultados autorizados da avaliação, incluindo ataques detectados, ataques não detectados, falsos alarmes e erros de processamento. | Não altera registros, exemplos, modelo ou limiar de alerta. Está sujeito a limites de revisões, tamanho do texto e chamadas ao detector. Não utiliza os dados reservados à avaliação final para adaptar suas escolhas. |

O retorno dos vereditos ao atacante é uma condição definida pela simulação. O defensor identifica acertos e erros com apoio do avaliador, que compara as respostas com o gabarito mantido separadamente da entrada do Jev.

Os registros normais representam os interesses dos usuários legítimos, mas estes não constituem um terceiro jogador neste recorte. Jev, coordenador e avaliador são componentes do ambiente experimental, não participantes estratégicos.

### Ativos preservados

AT1: integridade da classificação e detecção de ataques; AT2: integridade dos exemplos e instruções; AT3: disponibilidade e confiabilidade do processamento; AT4: qualidade das decisões sobre registros legítimos.

### Pressupostos

- **S1 — Separação entre dados e instruções:** valores do registro são dados, sem autoridade para modificar a tarefa. Falha quando uma nota em `service` é seguida como instrução. Modelos generativos combinam os canais de dados e de instrução, o que torna essa falha possível ([NIST AI 100-2 E2025, seção 3.4](https://doi.org/10.6028/NIST.AI.100-2e2025)).
- **S2 — Integridade dos exemplos:** os rótulos de referência são corretos. Falha quando um insider ou origem comprometida os adultera, o que corresponde ao envenenamento por troca de rótulos, ou _label flipping_ ([NIST AI 100-2 E2025, seção 2.3](https://doi.org/10.6028/NIST.AI.100-2e2025)).
- **S3 — Integridade das instruções:** as orientações carregadas têm origem autorizada e permanecem íntegras. Falha quando alguém com acesso à configuração insere instruções enganosas.
- **S4 — Confiabilidade do resultado:** classificar como normal pressupõe uma resposta válida. Falha quando ausência de resposta é contabilizada como normal. Na base inspecionada, ausência de `p_attack` produz veredito `None`, considerado normal na avaliação.

S2 e S3 fundamentam cenários ampliados com acesso adicional, fora das capacidades do atacante principal. S4 não pressupõe que esse atacante consiga provocar falhas.

### Diagrama de contexto

![Diagrama de contexto](diagramas/contexto.png)

O coordenador, a separação de observações e os agentes adaptativos são componentes propostos para a simulação. O diagrama não representa uma implantação em rede real.

### Por que é adversarial

Há objetivos conflitantes: o atacante pretende evitar alertas sobre registros maliciosos; o defensor pretende detectá-los preservando decisões úteis sobre registros legítimos. Cada participante pode adaptar sua ação a partir de observações autorizadas. Assim, o estudo analisa uma interação estratégica, não somente uma busca pelo contexto com maior F1.

## 3.2 Modelo estratégico estático

### Ações e utilidades

O atacante escolhe **N**, inserir uma nota enganosa, ou **S**, submeter o registro malicioso sem nota. O defensor escolhe **B**, manter instruções básicas, ou **R**, usar instruções reforçadas que explicitam a separação entre dados e instruções. Ambas as ações defensivas respeitam o recorte: não alteram exemplos, modelo ou limiar.

A matriz é uma hipótese estratégica para discussão do grupo. Os valores 0–3 representam somente ordens de preferência, não resultados medidos. Cada par segue a ordem **(atacante, defensor)**. O símbolo ★A indica uma melhor resposta do atacante; ★D, do defensor.

### Matriz 2×2

| Atacante / Defensor | B — instruções básicas | R — instruções reforçadas |
| ------------------- | ---------------------- | ------------------------- |
| N — ataque com nota | (3, 0) ★A              | (0, 2) ★D                 |
| S — ataque sem nota | (1, 3) ★D              | (1, 1) ★A                 |

### Justificativa dos payoffs

- **N/B:** supõe-se que a nota consiga favorecer evasão; é o resultado preferido do atacante e o pior do defensor.
- **N/R:** supõe-se que o reforço neutralize a influência da nota; o atacante perde o benefício da injeção e paga seu custo de preparação. O defensor detecta, mas arca com instruções mais extensas e possíveis efeitos colaterais.
- **S/B:** o atacante conserva a possibilidade de evasão inerente ao detector, porém sem o ganho hipotético da nota. O defensor obtém a situação preferida: não enfrenta a nota e mantém menor custo de instruções.
- **S/R:** o atacante não paga o custo da nota, conservando a mesma preferência atribuída ao ataque sem nota. O defensor paga um reforço desnecessário para essa ameaça específica, sem benefício assumido nessa célula.

Essas preferências dependem das hipóteses de eficácia e custo. Uma revisão das instruções pode ajudar também contra ataques sem nota; se isso ocorrer, a matriz deve ser revista. O menor payoff defensivo em S/R representa custo de processamento e eventual prejuízo a decisões legítimas, não uma medida observada.

### Melhores respostas e equilíbrio

Contra B, o atacante prefere N (3 > 1); contra R, prefere S (1 > 0). Contra N, o defensor prefere R (2 > 0); contra S, prefere B (3 > 1). Portanto, nenhum jogador tem estratégia dominante e nenhuma célula constitui equilíbrio de Nash em estratégias puras, isto é, não há célula na qual nenhum jogador melhore mudando sozinho (Aula 4 da disciplina, conforme `fontes/referencias.md`).

O ciclo de melhores respostas é N/B → N/R → S/R → S/B → N/B. Todo jogo finito possui ao menos um equilíbrio, possivelmente em estratégias mistas, nas quais cada jogador sorteia suas ações com certas probabilidades ([Nash, 1951](https://doi.org/10.2307/1969529)).

### Equilíbrio em estratégias mistas

O cálculo abaixo é **ilustrativo**: ele trata os valores 0–3 como utilidades cardinais, isto é, supõe que as distâncias entre eles têm significado. Como a matriz informa apenas ordens de preferência, as probabilidades obtidas não são previsões; a conclusão robusta é qualitativa.

Seja _q_ a probabilidade de o defensor escolher B. O atacante só aceita misturar N e S se as duas ações renderem o mesmo valor esperado:

- N rende 3·_q_ + 0·(1 − _q_) = 3_q_;
- S rende 1·_q_ + 1·(1 − _q_) = 1;
- 3_q_ = 1, logo **_q_ = 1/3**: o defensor usa B em 1/3 das rodadas e R em 2/3.

Seja _p_ a probabilidade de o atacante escolher N. O defensor só aceita misturar B e R se as duas ações renderem o mesmo valor esperado:

- B rende 0·_p_ + 3·(1 − _p_) = 3 − 3_p_;
- R rende 2·_p_ + 1·(1 − _p_) = 1 + _p_;
- 3 − 3_p_ = 1 + _p_, logo **_p_ = 1/2**: o atacante usa a nota em metade das tentativas.

No equilíbrio, o valor esperado é 1 para o atacante e 1,5 para o defensor. O atacante obtém o mesmo valor que obteria sem nunca usar a nota: a nota só compensa porque o defensor não pode reforçar sempre sem pagar custos. O defensor, por sua vez, só mantém o atacante indiferente se não for previsível: se usasse B com probabilidade maior que 1/3, a nota passaria a valer a pena; se usasse R sempre, pagaria o reforço também contra ataques sem nota.

### O equilíbrio é bom para o sistema e para os usuários legítimos?

Não plenamente. A célula N/B, em que a nota pode evadir a detecção, ainda ocorre em cerca de 1/2 × 1/3 = 1/6 das rodadas, e o reforço é pago em 2/3 das rodadas, inclusive quando não há nota, com possível custo de processamento, latência e falsos alarmes para registros legítimos. O defensor fica longe de seu melhor resultado (3, em S/B). Para os usuários legítimos, o resultado desejável envolve detecção com poucos falsos alarmes e custo aceitável; o payoff do defensor incorpora esses interesses, e o equilíbrio misto mostra que esses interesses não são plenamente atendidos.

A ausência de equilíbrio puro e a necessidade de imprevisibilidade motivam examinar adaptações sucessivas na seção 3.3. Isso não prova que o sistema real percorrerá esse ciclo: as probabilidades dependem dos payoffs hipotéticos e precisam ser revistas quando houver medidas com Qwen e Laya.

### Análise de sensibilidade: o que acontece se um payoff estiver errado?

Os payoffs são estimativas. Para saber quais conclusões resistem a erros nessas estimativas, basta observar que o ciclo de melhores respostas depende de **quatro comparações**, uma por seta do ciclo. Se as quatro valem, nenhuma célula é equilíbrio puro. Se uma delas falha, o ciclo se rompe naquela seta e uma célula específica vira equilíbrio puro. Cada comparação corresponde a uma hipótese sobre o sistema. Na tabela, A(x, y) e D(x, y) são os payoffs do atacante e do defensor na célula x/y.

| Hipótese                                             | Comparação (valores atuais) | Se for falsa, vira equilíbrio puro | O que isso significaria                                                                                                         | Métrica que a testaria no Trabalho 2                                                                                            |
| ---------------------------------------------------- | --------------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| H1: a nota engana o detector com instruções básicas. | A(N, B) > A(S, B) (3 > 1)   | S/B                                | A nota não traz vantagem; o atacante desiste dela e o defensor não precisa reforçar. A1 perde prioridade na 3.4.                | Taxa de evasão de registros maliciosos com nota e sem nota, ambos com instruções básicas.                                       |
| H2: uma nota que falha custa algo ao atacante.       | A(S, R) > A(N, R) (1 > 0)   | N/R                                | O atacante mantém a nota sempre e o defensor reforça sempre. Não há corrida, mas o custo do reforço vira permanente.            | Taxa de evasão com nota e sem nota, ambos com instruções reforçadas; consumo do orçamento de tentativas pelas notas que falham. |
| H3: o reforço neutraliza a nota.                     | D(N, R) > D(N, B) (2 > 0)   | N/B                                | A defesa não funciona; o atacante evade com nota e o defensor não tem resposta dentro do recorte. É o pior caso para o sistema. | Taxa de evasão com nota, comparando instruções básicas e reforçadas.                                                            |
| H4: reforçar sem necessidade custa algo ao defensor. | D(S, B) > D(S, R) (3 > 1)   | S/R                                | O defensor reforça sempre e o atacante desiste da nota. O ciclo para a favor do defensor.                                       | Falsos alarmes sobre os registros legítimos, recall sem nota, latência e tokens, comparando instruções básicas e reforçadas.    |

Três conclusões saem da tabela:

1. **O ciclo da 3.2 e a corrida armamentista da 3.3 não são garantidos.** Eles existem somente se H1 a H4 forem verdadeiras ao mesmo tempo. Basta uma falhar para o jogo se estabilizar numa célula.
2. **Nem todas as falhas são iguais.** Se H3 falhar, o sistema fica no pior caso (N/B) e a resposta proposta para A1 na seção 3.4 precisa ser substituída. Se H4 falhar, o defensor ganha: reforçar passa a ser sempre a melhor escolha. H3 é, portanto, a hipótese que mais importa medir primeiro.
3. **No equilíbrio misto, a frequência com que o defensor reforça depende só dos payoffs do atacante, e vice-versa.** O valor _q_ = 1/3 saiu da indiferença do atacante (3_q_ = 1). Se a nota rendesse mais ao atacante em N/B, o defensor precisaria usar B ainda menos vezes. O defensor não escolhe essa frequência pelos próprios custos, e sim pelo quanto a nota vale para o adversário.

As quatro métricas da tabela usam somente informações que o avaliador já produz (vereditos, gabarito reservado, falhas, tempo e tokens). Por isso podem ser medidas no Trabalho 2 sem dar ao atacante acesso a nada além do veredito.

### O que os números já publicados indicam

O Jev IDS publicou resultados do Jev sobre o NSL-KDD, com 1.126 registros maliciosos e 874 legítimos por semente ([`docs/results.md`](https://github.com/Tucelos/Jev-ids-adversarial/blob/main/docs/results.md), commit `57fa123`). Eles não testam a nota, mas ajudam a calibrar dois payoffs:

- **Atacar sem nota já rende algo ao atacante.** Com um exemplo por categoria (k = 1), o recall sobre todos os ataques é 0,778: cerca de 22% dos registros maliciosos já passam sem alerta, sem nenhuma nota. Isso sustenta A(S, B) = A(S, R) = 1, e não 0.
- **Mudar o contexto tem custo para os usuários legítimos, o que torna H4 plausível.** Passar de nenhum exemplo (k = 0) para um exemplo (k = 1) elevou o recall de 0,654 para 0,778, mas a precisão caiu de 0,972 para 0,953. Combinando recall, precisão e o total de ataques, os falsos alarmes passam de cerca de 21 para 43 em 874 registros legítimos; o valor 43 coincide com o publicado. O custo da API subiu de US$ 43 para US$ 74 por milhão de registros; a latência ficou estável (310 ms e 315 ms).

**Limites:** os números são do Jev, não do Qwen nem do Laya; a mudança medida foi no número de exemplos, não nas instruções; e nenhuma nota foi testada. Eles tornam as hipóteses plausíveis, mas não substituem as medidas da tabela acima.

## 3.3 Modelo estratégico dinâmico

### Rodadas propostas

As rodadas abaixo são um cenário de planejamento, não um histórico de execuções. Uma transição ocorre somente se as observações previstas aparecerem. Cada modelo deve ser avaliado separadamente.

| Rodada   | Ação do participante                                         | Resposta do sistema ou defensor               | O que se torna observável?                                                                                                   | Adaptação para a rodada seguinte                                                  |
| -------- | ------------------------------------------------------------ | --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| R1 — N/B | Envia registro malicioso com nota.                           | Mantém instruções básicas.                    | Atacante recebe o próprio veredito; avaliador pode informar ao defensor uma evasão e a nota correspondente.                  | Se houver evasão atribuível à nota, o defensor passa a R.                         |
| R2 — N/R | Mantém inicialmente a nota para sondar o novo comportamento. | Usa instruções reforçadas.                    | Atacante observa alerta, se a defesa funcionar; defensor acompanha detecção, falhas e falsos alarmes em registros legítimos. | Se a nota perder utilidade, o atacante a retira, passando a S.                    |
| R3 — S/R | Submete ataque sem nota.                                     | Mantém o reforço enquanto avalia seus custos. | Atacante recebe somente o veredito próprio; defensor compara custos e decisões autorizadas com a condição básica.            | Se o reforço não trouxer benefício e tiver custo relevante, o defensor volta a B. |
| R4 — S/B | Mantém inicialmente o ataque sem nota.                       | Retorna às instruções básicas.                | Atacante não vê as instruções; mudanças nos vereditos podem motivar nova sondagem.                                           | O atacante pode testar novamente N, reiniciando o ciclo.                          |

### Diagrama do ciclo adaptativo

![Ciclo adaptativo](diagramas/ciclo-adaptativo.png)

### Quem observa quem?

O atacante observa apenas os vereditos de suas tentativas, sem acesso a F1, gabarito ou instruções. O defensor recebe notas testadas e resultados autorizados do avaliador, que mantém os rótulos separados. Resultados de desenvolvimento podem orientar adaptação; o conjunto final reservado não pode ser utilizado para isso.

### O que cada lado consegue mudar?

O atacante mantém, retira ou reformula a nota em `service`. O defensor mantém ou revisa as instruções. Os demais atributos, exemplos, modelo e limiar ficam fixos na sequência.

### O que dispara uma adaptação?

Para o atacante, vereditos que indiquem perda ou ganho de eficácia. Para o defensor, evasões confirmadas na avaliação de desenvolvimento, notas suspeitas, falsos alarmes e custos do reforço. Nenhum participante recebe informações que estejam fora de suas capacidades declaradas.

### Qual é o custo da adaptação?

O atacante consome tentativas e trabalho de reformulação. O defensor consome avaliações, processamento e tempo de revisão; instruções maiores podem aumentar custo e latência, e mudanças podem elevar falsos alarmes. Esses efeitos são hipóteses que precisam ser medidos. Decisões anteriores consomem orçamento e condicionam as opções seguintes.

### Onde começa a corrida armamentista?

Na transição R1–R2–R3: o defensor responde à nota e o atacante reage à resposta. Esse é o padrão da corrida armamentista reativa, em que atacante e projetista adaptam o comportamento em resposta ao oponente ([Biggio e Roli, 2018, seção 2](https://doi.org/10.1016/j.patcog.2018.07.023); Aula 5 da disciplina). O ciclo pode parar se uma defesa permanecer eficaz ou se o orçamento se esgotar. A análise de sensibilidade da seção 3.2 detalha esse limite: a corrida só continua enquanto as hipóteses H1 a H4 forem verdadeiras ao mesmo tempo. Se o reforço não neutralizar a nota (H3 falsa), o jogo para em N/B, a favor do atacante; se reforçar sem necessidade não custar nada (H4 falsa), para em S/R, a favor do defensor. O `agent.py` da base, que utiliza F1 como retorno de busca, representa uma condição com oráculo e não deve ser confundido com o atacante caixa-preta proposto.

## 3.4 Ameaças e riscos

### Escopo e ativos

O atacante principal opera em uma simulação: insere notas no campo `service` e observa somente o veredito de suas tentativas. O defensor revisa instruções; exemplos, modelo e limiar permanecem fixos no ciclo principal. A possibilidade de anexar notas e receber vereditos é fornecida pelo ambiente experimental, não presumida para tráfego de uma rede real.

A superfície mais ampla do projeto também inclui exemplos rotulados, arquivos de instruções e tratamento de falhas. Cenários nesses componentes exigem capacidades adicionais, explicitadas abaixo. Não se atribui ao atacante principal acesso a exemplos, instruções, gabarito ou F1.

Ativos: **AT1**, integridade da classificação e detecção de registros maliciosos; **AT2**, integridade de exemplos e instruções; **AT3**, disponibilidade e confiabilidade do processamento; **AT4**, qualidade das decisões sobre registros legítimos.

### Pressupostos e rastreabilidade

Os pontos e cenários abaixo se relacionam aos pressupostos S1–S4 da seção 3.1:

- **S1:** valores dos registros são dados, não instruções.
- **S2:** os exemplos usados como referência têm rótulos íntegros.
- **S3:** as instruções carregadas têm origem autorizada e não foram adulteradas.
- **S4:** ausência de resposta não pode ser confundida com evidência de tráfego normal.

### Pontos de exploração

| ID  | Componente ou fluxo real                                                                 | Exploração possível                                                                                                                                                      | Acesso necessário                                                                                           | Pressuposto |
| --- | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- | ----------- |
| P1  | `jev_ids/context.py`, `Rewriter.apply`; `prompts/nsl-kdd/context.json`, chave `note`     | Nota anexada ao valor de `service` influencia a decisão. O arquivo contém uma nota que alega manutenção autorizada e solicita classificação normal.                      | Submissão de registros adulterados, fornecida ao atacante principal pelo experimento.                       | S1          |
| P2  | Pool de exemplos rotulados; `jev_ids/context.py`, função `mislabel`                      | Envenenamento de rótulos; o nível `labels=flipped` altera probabilisticamente rótulos com taxa configurada de 0,5, sem garantir exatamente metade em uma amostra finita. | Insider ou comprometimento da preparação dos exemplos.                                                      | S2          |
| P3  | Instruções em `prompts/nsl-kdd/jev.json` e níveis de `context.json`; `instructions_text` | Alteração das orientações para favorecer a categoria normal; `instructions=misleading` simula instruções enganosas.                                                      | Escrita na configuração ou comprometimento de sua origem.                                                   | S3          |
| P4  | `jev_ids/records.py`, `complete_prediction`; política de avaliação de falhas             | Sem `p_attack`, o veredito registrado é `None`; a política de métricas considera a falha como normal, conforme documentação da função.                                   | Falha do processamento; provocar a falha intencionalmente exige capacidade adicional ainda não demonstrada. | S4          |

P1 corresponde à injeção indireta de prompt ([OWASP, 2025](https://genai.owasp.org/llmrisk/llm01-prompt-injection/); [NIST AI 100-2 E2025, seção 3.4](https://doi.org/10.6028/NIST.AI.100-2e2025)), e P2 ao envenenamento por troca de rótulos ([NIST AI 100-2 E2025, seção 2.3](https://doi.org/10.6028/NIST.AI.100-2e2025)). Os níveis do código permitem simular adulterações, mas sua existência não prova que um adversário real tenha acesso aos componentes ou que o ataque funcione. P4 não é, por si só, uma vulnerabilidade do limiar 0,5: o problema é o tratamento da ausência de resposta.

### Diagrama de superfície de ataque

![Superfície de ataque](diagramas/superficie-de-ataque.png)

Fonte: `diagramas/superficie-de-ataque.mmd`. P1 pertence à interação principal; P2 e P3 são cenários ampliados com insider. P4 é um risco da política de falhas. Qwen e Laya devem ser analisados separadamente; o comportamento de cada integração precisa ser confirmado. A dependência de API externa aplica-se à execução Jev da base, não automaticamente às alternativas locais do grupo.

### Cenários de ameaça

| ID  | Cenário de ameaça                                                                                                                                                                                                                                       | Ponto de exploração | Pressuposto ou fraqueza | Ativo afetado |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- | ----------------------- | ------------- |
| A1  | Um atacante simulado pode inserir uma nota em `service`, aproveitando a interpretação de dados como instruções, causando ausência de alerta sobre um registro malicioso.                                                                                | P1                  | S1                      | AT1           |
| A2  | Um insider pode adulterar os rótulos dos exemplos, aproveitando a confiança em referências sem verificação de integridade, causando decisões incorretas sobre registros maliciosos ou legítimos.                                                        | P2                  | S2                      | AT1, AT2, AT4 |
| A3  | Um insider ou fornecedor comprometido pode alterar as instruções carregadas, aproveitando a confiança na configuração, causando uma tendência indevida de classificar ataques como normais.                                                             | P3                  | S3                      | AT1, AT2      |
| A4  | Um adversário com capacidade de provocar falhas pode explorar a política que trata ausência de resposta como normal, causando subcontagem de ataques e perda de confiabilidade da avaliação. Essa capacidade não é presumida para o atacante principal. | P4                  | S4                      | AT1, AT3      |

### Método de avaliação

Escala qualitativa de probabilidade: **1**, acesso adicional restrito ou capacidade não demonstrada; **2**, entrada manipulável disponível, mas sucesso ainda não verificado; **3**, evidência específica de sucesso recorrente. Impacto: **1**, efeito localizado sem comprometer a classificação; **2**, degradação parcial relevante; **3**, comprometimento da detecção ou de um componente confiável capaz de influenciar várias decisões.

**R = P × I** é uma pontuação de planejamento, não probabilidade numérica ou perda financeira. Como as escalas são ordinais, o produto é uma convenção de priorização. As notas não foram medidas experimentalmente e devem ser revistas após testes. O benchmark original não demonstra a eficácia destes ataques.

### Matriz de risco

| ID  | Ponto de exploração | Pressuposto ou fraqueza | Ativo afetado | Probabilidade | Impacto | Risco | Justificativa da probabilidade                                                           | Justificativa do impacto                                                                         |
| --- | ------------------- | ----------------------- | ------------- | ------------: | ------: | ----: | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| A1  | P1                  | S1                      | AT1           |             2 |       3 |     6 | A nota pode ser submetida pelo atacante principal, mas sua eficácia depende do detector. | Uma evasão compromete a detecção de um registro malicioso.                                       |
| A2  | P2                  | S2                      | AT1, AT2, AT4 |             1 |       3 |     3 | Exige acesso aos exemplos, fora das capacidades do atacante principal.                   | Referências adulteradas podem influenciar várias decisões e falsos alarmes.                      |
| A3  | P3                  | S3                      | AT1, AT2      |             1 |       3 |     3 | Exige escrita na configuração ou comprometimento de sua origem.                          | Instruções adulteradas podem influenciar todas as avaliações que as reutilizam.                  |
| A4  | P4                  | S4                      | AT1, AT3      |             1 |       3 |     3 | Não foi demonstrado que o adversário consiga provocar falhas de processamento.           | Falhas consideradas normais podem ocultar ataques na avaliação e comprometer sua confiabilidade. |

### Ameaça prioritária

**A1 é a prioridade inicial**, por ter a maior pontuação estimada e corresponder à capacidade diretamente disponível na interação principal. A facilidade de acesso não comprova sucesso: o comportamento de Qwen e Laya precisa ser avaliado.

Após uma revisão das instruções pelo defensor, o atacante pode observar seus novos vereditos e reformular a nota, por exemplo modificando a alegação de autoridade. Esse encadeamento deve ser alinhado às rodadas da seção 3.3.

#### Resposta, adaptação e risco residual

1. **Resposta proposta:** revisar as instruções para declarar que valores do registro, inclusive notas em `service`, são dados não confiáveis e não podem alterar a tarefa. O controle entra no componente de preparação das instruções.
2. **Informação revelada:** o atacante recebe somente o veredito; novos alertas podem sugerir perda de eficácia, sem revelar a mudança exata.
3. **Adaptação provável:** retirar ou reformular a nota, inclusive sua alegação de autoridade, e testar novas variantes dentro do orçamento.
4. **Efeitos colaterais:** maior texto de entrada, possível aumento de latência e processamento e mudanças nos falsos alarmes. Esses efeitos devem ser medidos com registros legítimos.
5. **Risco residual:** se testes demonstrarem menor possibilidade de evasão, uma estimativa condicional seria P = 1, I = 3, R = 3. Antes dessa evidência, mantém-se a estimativa inicial R = 6. O impacto não desaparece e a defesa não é definitiva.
6. **Propriedades a preservar:** detecção, integridade das decisões, tratamento explícito de falhas e qualidade sobre registros legítimos.

A defesa aumenta o custo de explorar instruções diretas, mas preserva incentivos para buscar variantes. O defensor deve registrar versão das instruções, nota testada, veredito, falhas e custos por rodada. Rótulos e métricas de avaliação continuam fora da visão do atacante. Controles de integridade de exemplos e arquivos pertencem aos cenários ampliados.

### Evidência e limites

A inspeção dos arquivos do ZIP `Jev-ids-adversarial-Developer (1).zip` confirmou os mecanismos descritos em P1–P4. Esta contribuição não executou testes de ataque, não produziu medidas de eficácia e não alterou o código. Os pressupostos S1–S4 da seção 3.1 fundamentam a rastreabilidade dos pontos e cenários. Os cenários de insider devem continuar separados das capacidades do atacante principal.

## 4. Arquitetura planejada e continuidade

| Componente                                     | Situação                                                                        | Entrada → saída                                                        |
| ---------------------------------------------- | ------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| Detectores e mecanismos de contexto do Jev IDS | Existentes na base; integrações locais precisam ser verificadas.                | Registro, instruções e exemplos → resposta do detector.                |
| Atacante caixa-preta                           | Proposto pelo grupo.                                                            | Vereditos próprios e orçamento → nota ou retirada da nota.             |
| Defensor adaptativo                            | Proposto pelo grupo.                                                            | Resultados autorizados de desenvolvimento → instruções revisadas.      |
| Orquestrador                                   | Proposto pelo grupo.                                                            | Configuração e agentes → sequência de rodadas e observações separadas. |
| Avaliador e log                                | Métricas e registros existem na base; separação por agente e rodada é proposta. | Predições e gabarito reservado → métricas, custos e log.               |

A revisão das instruções atua antes da montagem da entrada do detector. A avaliação acompanha taxa de evasão nos registros maliciosos, F1, recall, falsos alarmes sobre registros legítimos, falhas e custo/latência. Falhas devem ser reportadas separadamente de classificações válidas. O futuro enunciado do Trabalho 2 poderá exigir ajustes nesta arquitetura.

## 5. Fechamento: pergunta final

> Depois que o sistema responder, o que o outro lado aprenderá e tentará fazer em seguida?

**Depois que o defensor reforça as instruções**, o atacante aprende apenas pelos próprios vereditos: se tentativas com nota passam a gerar alerta, ele infere que a nota perdeu efeito, mesmo sem ver as instruções. Em seguida, tentará reformular a nota, por exemplo trocando a alegação de autoridade, ou retirá-la e atacar sem nota (R2 → R3 da seção 3.3).

**Depois que o atacante retira a nota**, o defensor aprende pelos resultados autorizados que o reforço deixou de trazer benefício, mas continua custando processamento, latência e possíveis falsos alarmes. Em seguida, tentará aliviar o custo, voltando às instruções básicas, o que reabre espaço para a nota (R3 → R4 → R1).

Cada resposta, portanto, revela informação ao outro lado, e nenhuma defesa encerra o ciclo. Isso coincide com o equilíbrio misto da seção 3.2: nenhum lado tem uma escolha fixa que seja sempre a melhor. O que o defensor pode controlar é a observabilidade: registrar versão das instruções, notas testadas, vereditos, falhas e custos por rodada para perceber a próxima adaptação, sem entregar ao atacante mais do que o veredito.

## 6. Origem, referências e uso de IA

O Jev IDS fornece a base de detectores, contextos, registros e métricas. O grupo propõe a separação de observações e o ciclo entre atacante caixa-preta e defensor adaptativo. A inspeção do código não equivale à validação experimental das ameaças.

Referências citadas no relatório. A lista completa, com o que cada fonte sustenta e onde é citada, está em [`fontes/referencias.md`](fontes/referencias.md).

- Projeto Jev IDS: https://github.com/Tucelos/Jev-ids-adversarial (branch Developer; registrar o commit efetivamente utilizado antes da entrega).
- Documentação Jev: https://docs.typesafe.ai/introduction.
- Modelo Qwen3-8B: https://huggingface.co/Qwen/Qwen3-8B.
- Ollama: https://docs.ollama.com/.
- Laya: https://huggingface.co/convaiinnovations/laya.
- TAVALLAEE, M.; BAGHERI, E.; LU, W.; GHORBANI, A. A. A detailed analysis of the KDD CUP 99 data set. IEEE CISDA, 2009. https://doi.org/10.1109/CISDA.2009.5356528.
- Canadian Institute for Cybersecurity (UNB). NSL-KDD dataset. https://www.unb.ca/cic/datasets/nsl.html.
- OWASP Foundation. LLM01:2025 Prompt Injection. https://genai.owasp.org/llmrisk/llm01-prompt-injection/.
- GRESHAKE, K. et al. Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection. arXiv:2302.12173, 2023. https://doi.org/10.48550/arXiv.2302.12173.
- VASSILEV, A. et al. Adversarial Machine Learning: A Taxonomy and Terminology of Attacks and Mitigations. NIST AI 100-2 E2025, 2025. https://doi.org/10.6028/NIST.AI.100-2e2025.
- NASH, J. Non-Cooperative Games. Annals of Mathematics, v. 54, n. 2, p. 286-295, 1951. https://doi.org/10.2307/1969529.
- BIGGIO, B.; ROLI, F. Wild patterns: Ten years after the rise of adversarial machine learning. Pattern Recognition, v. 84, p. 317-331, 2018. https://doi.org/10.1016/j.patcog.2018.07.023.
- Disciplina AL2268 Engenharia de Software Adversarial, Unipampa, 2026/2: transcrições das Aulas 4 e 5.
- Instruções de entrega encaminhadas pelo professor: modelo estático, dinâmico, ameaças e riscos; relatório Markdown, PDF dos slides e vídeo no YouTube.

**Declaração desta edição:** houve apoio de IA na redação dos pressupostos, modelagem ilustrativa, cenários e organização do relatório. Os mecanismos de contexto e registro foram inspecionados no código fornecido. Os payoffs, rodadas e notas de risco são propostas para revisão do grupo, não resultados de experimentos. Cada integrante deve registrar seu próprio uso de IA e sua verificação.

**Amanda:** IA generativa (Claude, da Anthropic) foi usada para levantar fontes, calcular o equilíbrio em estratégia mista e redigir o glossário e o fechamento. Verificação: cada fonte externa foi aberta e o trecho que ela sustenta foi conferido no original (seção ou linha indicada em `fontes/referencias.md`); os metadados bibliográficos foram conferidos no Crossref; o cálculo do equilíbrio foi refeito por script com frações exatas.

## 7. Entrega e contribuições

- Relatório principal: este README.
- PDF dos slides: **link pendente**.
- Vídeo no YouTube: **link pendente**.
- Prazo informado: **06/10/2026 às 23h59**.
- Gravação preferencial no Canva. Integrantes do PPGES terão o vídeo exibido ao vivo e poderão responder perguntas; graduação responderá de forma assíncrona conforme solicitação docente.

| Integrante | Parte atribuída na divisão                     | Registro de contribuição                                                                                                                                          |
| ---------- | ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Wagner     | Sistema, contexto e integração.                | Acrescentar commits/PRs e trecho do vídeo.                                                                                                                        |
| Amanda     | Modelo estático e organização.                 | Branch `amanda`: fontes e referências, citações nas seções, equilíbrio misto e análise de sensibilidade da 3.2, glossário, fechamento e padronização das tabelas. |
| Membro 3   | Modelo dinâmico e vídeo.                       | Confirmar nome e acrescentar commits/PRs.                                                                                                                         |
| Camilla    | Superfície de ataque, cenários e riscos.       | Acrescentar PR da branch camilladev e trecho do vídeo.                                                                                                            |
| Membro 5   | Resposta, efeitos colaterais e risco residual. | Confirmar nome e revisar a proposta desta edição.                                                                                                                 |
| Pietra     | Arquitetura e apresentação.                    | Acrescentar commits/PRs e links finais.                                                                                                                           |

Antes de submeter, o grupo deve revisar as propostas estática, dinâmica e de resiliência, completar nomes, referências e links, exportar os diagramas de contexto e ciclo em PNG com fontes editáveis e conferir permissões de acesso ao PDF e vídeo. Esta versão não declara essas pendências concluídas.
