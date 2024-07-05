ARG VERSION=master-ubuntu_jammy
FROM openstackhelm/keystone:${VERSION} as build
RUN apt update && apt install -y git
RUN /var/lib/openstack/bin/pip install --upgrade --force-reinstall pip
WORKDIR /opt/keystone-rxt
COPY . /opt/keystone-rxt
RUN ls -al /opt/keystone-rxt/
RUN /var/lib/openstack/bin/pip install --no-cache-dir -e git+file:///opt/keystone-rxt#egg=keystone-rxt
RUN find /var/lib/openstack -regex '^.*\(__pycache__\|\.py[co]\)$' -delete

FROM openstackhelm/keystone:${VERSION}
COPY --from=build /var/lib/openstack/. /var/lib/openstack/
