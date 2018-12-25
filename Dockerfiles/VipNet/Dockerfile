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

WORKDIR /app
ADD SignOVService/dist/deb/ csp/
WORKDIR /app/csp
#BASE
RUN dpkg -i itcs-licensing_*_amd64.deb
RUN dpkg -i itcs-entropy-gost_*_amd64.deb
RUN dpkg -i itcs-winapi_*_amd64.deb
RUN dpkg -i itcs-csp-gost_*_amd64.deb
#DEV
RUN dpkg -i itcs-csp-dev_*_all.deb
#SOFT TOKEN
RUN dpkg -i itcs-softtoken_*_amd64.deb

#�������� ��������� ��������� ����� � ��������� ���������
ADD SignOVService/certs/TestCertificate/PrivateKey/ /var/opt/itcs/vipnet-csp/containers/
#�������� ����������
ADD SignOVService/certs/TestCertificate/Testovaia_organizatciia_VipNet.cer /app/Testovaia_organizatciia_VipNet.cer
#������������� ���������� � ��������� ���������
RUN /opt/itcs/bin/certmgr add_certificate --location=CurrentUser --store=My --file=/app/Testovaia_organizatciia_VipNet.cer --container=/var/opt/itcs/vipnet-csp/containers/rnd-B-B226-18DD-4FCC-97B7-7FEB-6BA3-9529
#������� ������ ������������� ������������
RUN /opt/itcs/bin/certmgr  print_certificates  --location=CurrentUser --store=My

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