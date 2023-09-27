openstack federation protocol delete --identity-provider rackspace rackspace
openstack project delete rackspace_cloud_project
openstack group delete rackspace_cloud_users
openstack domain set --name rackspace_cloud_domain --disable rackspace_cloud_domain
openstack domain delete rackspace_cloud_domain
openstack mapping delete rackspace_mapping