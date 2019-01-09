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

#RUN apt-get update
#RUN apt-get install -y lsb lsb-core alien


ADD SignOVService/dist/ /tmp/dist/
ADD SignOVService/certs/ /tmp/cert/

RUN tar -zxf /tmp/dist/linux-amd64_deb.tgz -C /tmp/dist/
RUN /tmp/dist/linux-amd64_deb/install.sh

RUN /opt/cprocsp/sbin/amd64/cpconfig -license -view

#RUN mkdir -p /var/opt/cprocsp/keys/root/ && mv /tmp/cert/CryptoPro/Gost2001_CryptoPro/abc.000 /var/opt/cprocsp/keys/root/
RUN mkdir -p /var/opt/cprocsp/keys/root/ && mv /tmp/cert/CryptoPro/Gost2012_256_CryptoPro/gost256c.000 /var/opt/cprocsp/keys/root/
RUN mkdir -p /var/opt/cprocsp/keys/root/ && mv /tmp/cert/CryptoPro/Gost2012_512_CryptoPro/gost512c.000 /var/opt/cprocsp/keys/root/

RUN chown root:root /var/opt/cprocsp/keys/root/ -R
RUN chmod -R 777 /var/opt/cprocsp/keys/root/

USER root

#RUN ls -la /var/opt/cprocsp/keys/root/

#RUN /opt/cprocsp/bin/amd64/certmgr -inst -store uMy -file /tmp/cert/CryptoPro/Gost2001_CryptoPro/omsk.cer -cont "\\\\.\\HDIMAGE\\abc"
RUN /opt/cprocsp/bin/amd64/certmgr -inst -store uMy -file /tmp/cert/CryptoPro/Gost2012_256_CryptoPro/gost256cp.cer -cont "\\\\.\\HDIMAGE\\gost256c"
RUN /opt/cprocsp/bin/amd64/certmgr -inst -store uMy -file /tmp/cert/CryptoPro/Gost2012_512_CryptoPro/gost512cp.cer -cont "\\\\.\\HDIMAGE\\gost512c"

#RUN /opt/cprocsp/bin/amd64/csptest -passwd -change '' -cont "\\\\.\\HDIMAGE\\abc" -passwd 123
RUN /opt/cprocsp/bin/amd64/csptest -passwd -change '' -cont "\\\\.\\HDIMAGE\\gost256c" -passwd gost256cp

#USER root
#
#RUN /opt/cprocsp/sbin/amd64/cpconfig -loglevel ocsp -mask 0xF
#RUN /opt/cprocsp/sbin/amd64/cpconfig -loglevel ocsp_fmt -mask 0x39
#RUN /opt/cprocsp/sbin/amd64/cpconfig -loglevel tsp -mask 0xF
#RUN /opt/cprocsp/sbin/amd64/cpconfig -loglevel tsp_fmt -mask 0x39
#RUN /opt/cprocsp/sbin/amd64/cpconfig -loglevel cades -mask 0xF
#RUN /opt/cprocsp/sbin/amd64/cpconfig -loglevel cades_fmt -mask 0x39
#
#RUN /opt/cprocsp/sbin/amd64/cpconfig -loglevel cpcsp -mask 0x3f
#RUN /opt/cprocsp/sbin/amd64/cpconfig -loglevel capi10 -mask 0x3f
#RUN /opt/cprocsp/sbin/amd64/cpconfig -loglevel cptext -mask 0x3f
#RUN /opt/cprocsp/sbin/amd64/cpconfig -loglevel capi20 -mask 0x3f
#RUN /opt/cprocsp/sbin/amd64/cpconfig -loglevel capilite -mask 0x3f
#RUN /opt/cprocsp/sbin/amd64/cpconfig -loglevel cryptsrv -mask 0x3f
#
#RUN /opt/cprocsp/sbin/amd64/cpconfig -loglevel cpcsp_fmt -mask 0x7f
#RUN /opt/cprocsp/sbin/amd64/cpconfig -loglevel capi10_fmt -mask 0x7f
#RUN /opt/cprocsp/sbin/amd64/cpconfig -loglevel ctext_fmt -mask 0x7f
#RUN /opt/cprocsp/sbin/amd64/cpconfig -loglevel capi20_fmt -mask 0x7f
#RUN /opt/cprocsp/sbin/amd64/cpconfig -loglevel capilite_fmt -mask 0x7f
#RUN /opt/cprocsp/sbin/amd64/cpconfig -loglevel cryptsrv_fmt -mask 0x7f

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