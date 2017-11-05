# tcp-session-hijacking-ipv6

O objetivo geral do trabalho é desenvolver uma aplicação usando raw sockets para sequestrar conexões TCP (TCP Session Hijacking):

  - compreender de maneira prá ca o mecanismo de comunicação por sockets.
  
  - entender o funcionamento dos protocolos da camada de rede e transporte e seus problemas de segurança em redes locais.


O sequestro de conexões TCP implica em interceptar uma conexão já estabelecida entre duas partes comunicantes e, então, se passar por uma delas enviados pacotes para a outra parte. A ideia é dessincronizar a comunicação existente entre um cliente e um servidor (por exemplo, através do envio de uma mensagem de encerramento de conexão para o cliente - TCP Half-Close) e assumir a iden dade do cliente nessa conexão.

Uma conexão TCP estabelecida é unicamente iden ficada por uma quádrupla contendo endereço IP de origem, porta de origem, endereço IP de des no e porta de des no. Adicionalmente, cada pacote possui um número de sequência (SEQ) que iden fica o primeiro byte enviado no seguimento e, possivelmente, um número de reconhecimento (ACK) que informa à outra parte que os bytes anteriores àquele número foram recebidos com sucesso. Uma das maiores dificuldades em sequestrar uma conexão TCP é descobrir/adivinhar os números SEQ/ACK dos pacotes, tendo em vista que esses são valores de 32 bits atribuídos pelo sistema operacional (ver RFC 793 para mais detalhes).

Quando empregado em uma rede local, o sequestro de conexões pode ser combinado com alguma técnica conhecida de man-in-the-middle (MITM). Neste caso, pode-se u lizar um programa sniffer (analisador de pacotes) para monitorar o tráfego de rede entre o cliente e o servidor e descobrir os próximos número SEQ/ACK de uma dada conexão. Nesse trabalho, usaremos um ataque do  po ARP Spoofing (ver ANEXO II) para interceptar o tráfego de rede do host alvo e descobrir as informações necessárias para realizar o sequestro de conexão. O funcionamento do ataque de sequestro de conexão está descrito no ANEXO I.

Todas as fases do desenvolvimento do trabalho devem ser documentadas na forma de um relatório. Este relatório deve primeiramente descrever o funcionamento do protocolo TCP e descrever como foi explorado o problema de segurança usando diagramas, trechos de códigos e/ou capturas de tela (sugestão: u lize capturas de telas do Wireshark para facilitar a explicação). Esse relatório deverá ser entregue juntamente com o código fonte u lizado.

## ANEXO I - Ataque TCP Session Hijaking

Uma vez que um ataque do  po man-in-the-middle na rede local foi realizado com sucesso, toda comunicação realizada entre a ví ma e a Internet passará pelo host atacante. Desta forma, é possível implementar um programa sniffer u lizando sockets raw que analisa os pacotes TCP trocados entre um cliente e um servidor a fim de descobrir as informações da conexão e realiza o sequestro.

O funcionamento básico do ataque é descrito nos passos a seguir:
- Passo 1: monitorar a comunicação entre o cliente e o servidor para descobrir as informações da conexão (as informações mais importantes são: porta de origem do cliente, número de sequência e número de reconhecimento);
- Passo 2: finalizar a conexão no lado do cliente, isto é, enviar um pacote de reset (RST) para o cliente;
- Passo 3: enviar dados para o servidor fingindo ser o cliente (enviar pelo menos um pacote para o servidor).
