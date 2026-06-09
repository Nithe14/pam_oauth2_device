FROM almalinux/9-base:latest AS builder

RUN dnf install -y 'dnf-command(config-manager)' \
    && dnf config-manager --set-enabled crb \
    && dnf install -y \
       gcc \
       git \
       pkgconfig \
       openssl-devel \
       pam-devel \
    && dnf clean all

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable

WORKDIR /build

COPY . .

RUN cargo build --release \
    && gcc -o target/pam_test test.c -lpam -lpam_misc

FROM almalinux:9-minimal

ARG TEST_USER=test
ENV TEST_USER=${TEST_USER}

RUN microdnf install -y \
       openssh-server \
       openssl \
       pam \
       valgrind \
       shadow-utils \
    && microdnf clean all \
    && rm -rf /var/cache/yum

COPY --from=builder /build/target/release/libpam_oauth2_device.so /usr/lib64/security/pam_oauth2_device.so
COPY --from=builder /build/target/pam_test /usr/libexec/pam_test

RUN mkdir -p /etc/pam_oauth2_device \
    && touch /var/log/pam_oauth2_device.log \
    && chmod 666 /var/log/pam_oauth2_device.log

COPY ./config.json /etc/pam_oauth2_device/config.json

RUN ssh-keygen -A

RUN sed -i 's/#UsePAM no/UsePAM yes/' /etc/ssh/sshd_config \
    && sed -i 's/#KbdInteractiveAuthentication no/KbdInteractiveAuthentication yes/' /etc/ssh/sshd_config \
    && if [ -f /etc/ssh/sshd_config.d/50-redhat.conf ]; then \
          sed -i 's/ChallengeResponseAuthentication no/KbdInteractiveAuthentication yes/g' /etc/ssh/sshd_config.d/50-redhat.conf; \
       fi

RUN useradd -m -s /bin/bash ${TEST_USER}

RUN sed -i '1s/^/auth        sufficient    pam_oauth2_device.so config=\/etc\/pam_oauth2_device\/config.json logs=\/var\/log\/pam_oauth2_device.log log_level=info\n/' /etc/pam.d/sshd

EXPOSE 22

CMD bash -c "tail -f /var/log/pam_oauth2_device.log & exec /usr/sbin/sshd -D"
