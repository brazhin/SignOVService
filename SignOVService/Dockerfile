FROM microsoft/aspnetcore:2.0 AS base
WORKDIR /app
EXPOSE 80

ENV NODE_VERSION 8.9.4
ENV NODE_DOWNLOAD_URL https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-x64.tar.gz
ENV NODE_DOWNLOAD_SHA 21fb4690e349f82d708ae766def01d7fec1b085ce1f5ab30d9bda8ee126ca8fc
RUN curl -SL "$NODE_DOWNLOAD_URL" --output nodejs.tar.gz \
     && echo "$NODE_DOWNLOAD_SHA nodejs.tar.gz" | sha256sum -c - \
     && tar -xzf "nodejs.tar.gz" -C /usr/local --strip-components=1 \
     && rm nodejs.tar.gz \
     && ln -s /usr/local/bin/node /usr/local/bin/nodejs
RUN npm install

#---------------------------------------------------------------------
RUN cat /etc/*-release

ARG HDIMAGE_STORE_NAME=abc.000
ARG HDIMAGE_STORE_PASSWORD=123
ARG CERT_FILE_NAME=omsk.cer

ADD SignOVService/dist/ /tmp/dist/
ADD SignOVService/cert/ /tmp/cert/

RUN tar -zxf /tmp/dist/linux-amd64_deb.tgz -C /tmp/dist/
#RUN tar -xzf /tmp/dist/cades_linux_amd64.tar.gz -C /tmp/dist/

# Установка КриптоПро CSP 4.0
RUN /tmp/dist/linux-amd64_deb/install.sh

# Номер лицензии (Если у вас есть лицензионный ключ, необходимо раскоментировать следующую строку и
# подставить свой серийный ключ вместо $CSP_LICENSE_KEY и раскоментировать его !!!)
#RUN /opt/cprocsp/sbin/amd64/cpconfig -license -set $CSP_LICENSE_KEY

# Проверка лицензии
RUN /opt/cprocsp/sbin/amd64/cpconfig -license -view

# Перенос закрытого ключа в HDIMAGE
RUN mkdir -p /var/opt/cprocsp/keys/root/ && mv /tmp/cert/abc.000 /var/opt/cprocsp/keys/root/

# даем права на чтение закрытого ключа пользователю $USER_NAME
RUN chown root:root /var/opt/cprocsp/keys/root/ -R
RUN chmod -R 777 /var/opt/cprocsp/keys/root/

USER root

#RUN ls -la /var/opt/cprocsp/keys/root/

# Добавляем сертификат в хранилище (от пользователя которым производим подпись)
#RUN /opt/cprocsp/bin/amd64/certmgr -inst -file /tmp/cert/$CERT_FILE_NAME -cont "\\\\.\\HDIMAGE\\$HDIMAGE_STORE_NAME"
#RUN /opt/cprocsp/bin/amd64/certmgr -inst -store uMy -file /root/certs/test_cert.cer -cont '\\.\HDIMAGE\$HDIMAGE_STORE_NAME'
#RUN /opt/cprocsp/bin/amd64/certmgr -inst -store uMy -cont /tmp/cert/abc.000

#RUN /opt/cprocsp/bin/amd64/csptestf -absorb -certs
#RUN /opt/cprocsp/bin/amd64/certmgr -list
#RUN /opt/cprocsp/bin/amd64/certmgr -inst -store uMy -file /tmp/cert/$CERT_FILE_NAME

RUN /opt/cprocsp/bin/amd64/csptest -keyset -enum_cont -fqcn -verifyc
RUN /opt/cprocsp/bin/amd64/certmgr -inst -store uMy -file /tmp/cert/$CERT_FILE_NAME -cont "\\\\.\\HDIMAGE\\abc"
RUN /opt/cprocsp/bin/amd64/certmgr -list

# Убираем пароль, чтобы он не кидал alert (Если хранилище уже не запаролено, то закоментить следующую строку)
RUN /opt/cprocsp/bin/amd64/csptest -passwd -change '' -cont "\\\\.\\HDIMAGE\\abc" -passwd 123

FROM microsoft/aspnetcore-build:2.0 AS build
WORKDIR /src
COPY ["SignOVService/SignOVService.csproj", "SignOVService/"]
RUN dotnet restore "SignOVService/SignOVService.csproj"
COPY . .
WORKDIR "/src/SignOVService"
RUN dotnet build "SignOVService.csproj" -c Release -o /app

FROM build AS publish
RUN dotnet publish "SignOVService.csproj" -c Release -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .

ENTRYPOINT ["dotnet", "SignOVService.dll"]