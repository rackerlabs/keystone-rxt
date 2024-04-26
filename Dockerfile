ARG VERSION=master-ubuntu_jammy
FROM openstackhelm/keystone:$VERSION
RUN /var/lib/openstack/bin/pip install --no-cache-dir keystone-rxt
