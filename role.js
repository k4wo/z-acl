'use strict';


class Role {

	constructor(roleId) {
		this.roleId = roleId.toString();
	}

	getId() {
		return this.roleId;
	}
}

module.exports = Role;