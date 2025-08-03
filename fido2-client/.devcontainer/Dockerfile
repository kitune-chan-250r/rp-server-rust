FROM ubuntu:latest

# ---- Install tools ----
RUN apt-get update
RUN apt-get install -y unzip screenfetch wget vim ca-certificates curl gnupg dnsutils git

# ---- Install oh-my-posh ----
# RUN curl -s https://ohmyposh.dev/install.sh | bash -s
RUN wget https://github.com/JanDeDobbeleer/oh-my-posh/releases/latest/download/posh-linux-amd64 -O /usr/local/bin/oh-my-posh
RUN chmod +x /usr/local/bin/oh-my-posh

RUN mkdir ~/.poshthemes
RUN wget https://github.com/JanDeDobbeleer/oh-my-posh/releases/latest/download/themes.zip -O ~/.poshthemes/themes.zip
RUN unzip ~/.poshthemes/themes.zip -d ~/.poshthemes
RUN chmod u+rw ~/.poshthemes/*.omp.*
RUN rm ~/.poshthemes/themes.zip
RUN echo 'eval "$(oh-my-posh init bash --config ~/.poshthemes/atomic.omp.json)"' >> ~/.bashrc

# ---- Install nodejs ----
RUN mkdir -p /etc/apt/keyrings
RUN curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
ARG NODE_MAJOR="21"
RUN echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list
RUN apt-get update
RUN apt-get install -y nodejs
