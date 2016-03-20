'use strict';


class Resource {

	constructor(resourceId) {
		this.resourceId = resourceId.toString();
	}

	getId() {
		return this.resourceId;
	}
}

module.exports = Resource;