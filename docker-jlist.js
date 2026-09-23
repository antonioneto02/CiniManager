const dockerController = require('./dashboard/docker-controller');
const { APP_REGISTRY, CONTAINER_NAME_OVERRIDES } = require('./dashboard/app-registry');

dockerController.snapshotOnce(APP_REGISTRY, CONTAINER_NAME_OVERRIDES)
  .then(out => { process.stdout.write(JSON.stringify(out)); process.exit(0); })
  .catch(err => { console.error(err); process.exit(1); });
