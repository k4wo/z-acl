'use strict';

const Role     = require('./role');
const Resource = require('./resource');
const Registry = require('./registry');
const oToArray = require('o-to-array');


class Acl {
	constructor() {
		this.roles              = new Registry('Role', Role);
		this.resources          = new Registry('Resource', Resource);
		this.rule               = {
			add: 'ADD',
			remove: 'REMOVE',
			allow: 'ALLOW',
			deny: 'DENY'
		};
		this.rules              = {
			allResources: {
				allRoles: {
					allPrivileges: {
						type: this.rule.deny,
						assert: null
					},
					byPrivilegeId: {}
				},
				byRoleId: {}
			},
			byResourceId: {}
		};
		this.isAllowedRole      = null;
		this.isAllowedResource  = null;
		this.isAllowedPrivilege = null;
	}

	addRole(role, parents) {
		this.roles.add(role, parents);

		return this;
	}

	getRole(role) {
		return this.roles.get(role);
	}

	hasRole(role) {
		return this.roles.has(role);
	}

	removeRole(role) {
		let roleId = this.roles.get(role).getId();

		this.roles.remove(role);
		delete this.rules.allResources.byRoleId[roleId];

		let byResourceId = this.rules.byResourceId;
		for( let resource in byResourceId ) {
			if( byResourceId[resource].byRoleId ) {
				delete byResourceId[resource].byRoleId[roleId];
			}
		}

		return this;
	}

	addResource(resource, parent) {
		if( Array.isArray(parent) ) {
			throw new TypeError(`Parent Resource can not be an Array.`);
		}

		this.resources.add(resource, parent);

		return this;
	}

	getResource(resource) {
		return this.resources.get(resource);
	}

	hasResource(resource) {
		return this.resources.has(resource);
	}

	removeResource(resource) {
		resource       = this.resources.getR(resource);
		let resourceId = resource.instance.getId();
		let parents    = resource.parents;
		let children   = resource.children;

		delete this.rules.byResourceId[resourceId];

		for( let parent in parents ) {
			delete this.resources.getR(parents[parent]).children[resourceId];
		}

		for( let child in children ) {
			let id = children[child].getId();
			this.removeResource(id);
		}

		this.resources.remove(resourceId);
		return this;
	}

	allow(roles, resources, privileges) {
		return this.setRule(this.rule.add, this.rule.allow, roles, resources, privileges);
	}

	deny(roles, resources, privileges) {
		this.setRule(this.rule.add, this.rule.deny, roles, resources, privileges);
	}

	removeAllow(roles, resources, privileges) {
		this.setRule(this.rule.remove, this.rule.allow, roles, resources, privileges);
	}

	removeDeny(roles, resources, privileges) {
		this.setRule(this.rule.remove, this.rule.deny, roles, resources, privileges);
	}

	setRule(operation, type, roles, resources, privileges) {
		if( this.rule.allow !== type && this.rule.deny !== type ) {
			throw new RangeError(`Unsupported rule type. Must be either ${this.rule.allow} or ${this.rule.deny}.`);
		}

		if( !Array.isArray(roles) ) {
			roles = [roles];
		}

		roles = roles.map(role => this.getRole(role));

		if( !Array.isArray(resources) ) {
			let keys = Object.keys(this.resources.getAll());

			if( !resources && keys.length ) {
				resources = keys;

				// Passing null resource make sure that allPrivilege is set
				if( resources.indexOf(null) === -1 ) {
					resources.push(null);
				}
			}
			else {
				resources = [resources];
			}
		} else if( !resources.length ) {
			resources = [null];
		}

		var resTmp = {};
		var len    = resources.length;
		for( let i = 0; i < len; i++ ) {
			if( resources[i] ) {
				let resourceObj = this.getResource(resources[i]);
				let resourceId  = resourceObj.getId();
				let children    = this.getChildResources(resourceObj);

				resTmp             = Object.assign(resTmp, children);
				resTmp[resourceId] = resourceObj;
			}
			else {
				resTmp[null] = null;
			}
		}
		resources = oToArray(resTmp);

		if( !privileges ) {
			privileges = [];
		}
		else if( !Array.isArray(privileges) ) {
			privileges = [privileges];
		}

		switch( operation ) {
			case this.rule.add:
				this.operationAdd(resources, roles, privileges, type);
				break;
			case this.rule.deny:
				this.operationRemove(resources, roles, privileges, type);
				break;
			default:
				throw new Error(`Unsupported operation. Must be either ${this.rule.add} or ${this.rule.deny}.`);
		}

		return this;
	}

	getChildResources(resource) {
		var result   = {};
		var id       = resource.getId();
		var children = this.resources.getR(id)['children'];

		for( let child in children ) {
			if( children.hasOwnProperty(child) ) {
				var resChildren    = this.getChildResources(children[child]);
				resChildren[child] = children[child];

				result = Object.assign(resChildren, result);
			}
		}

		return result;
	}

	operationAdd(resources, roles, privileges, type) {
		let resLen = resources.length;
		let rolLen = roles.length;

		for( let i = 0; i < resLen; i++ ) {
			for( let j = 0; j < rolLen; j++ ) {
				const rules = this.getRules(resources[i], roles[j], true);

				if( !privileges.length ) {
					if( !rules.allPrivileges ) {
						rules.allPrivileges = {};
					}

					rules.allPrivileges.type   = type;
					rules.allPrivileges.assert = null;

					if( !rules.byPrivilegeId ) {
						rules.byPrivilegeId = {};
					}
				}
				else {
					for( let k = 0; k < privileges.length; k++ ) {
						if( !rules.byPrivilegeId[privileges[k]] ) {
							rules.byPrivilegeId[privileges[k]] = {};
						}

						rules.byPrivilegeId[privileges[k]]['type']   = type;
						rules.byPrivilegeId[privileges[k]]['assert'] = null;
					}
				}
			}
		}
	}

	operationRemove(resources, roles, privileges, type) {
		let resLen = resources.length;
		let rolLen = roles.length;

		for( let i = 0; i < resLen; i++ ) {
			for( let j = 0; j < rolLen; j++ ) {

				var rules = this.getRules(resources[i], roles[j], true);
				if( !rules ) {
					continue;
				}

				if( !privileges.length ) {
					if( !resources && !roles ) {
						if( type === rules.allPrivileges.type ) {
							rules = {
								allPrivileges: {
									type: this.rule.deny
								},
								byPrivilegeId: {}
							};
						}
						continue;
					}

					if( rules.allPrivileges.type & rules.allPrivileges.type === type ) {
						delete rules.allPrivileges;
					}
				}
				else {
					const privLen = privileges.length;

					for( let i = 0; i < privLen; i++ ) {
						let privi = rules.byPrivilegeId[privileges[i]];
						if( privi && privi === type ) {
							delete rules.byPrivilegeId[privileges[i]];
						}
					}
				}
			}
		}
	}

	getRules(resource, role, create) {
		const resourceRule = this.getResourceFromRules(resource, create);

		return this.getRoleFromRules(resourceRule, role, create);
	}

	getResourceFromRules(resource, create) {
		if( !resource ) {
			return this.rules.allResources;
		}

		const resourceId = resource.getId();
		if( !this.rules.byResourceId[resourceId] ) {
			if( !create ) {
				return;
			}

			this.rules.byResourceId[resourceId] = {
				byRoleId: {}
			};
		}

		return this.rules.byResourceId[resourceId];
	}

	getRoleFromRules(resource, role, create) {
		if( !role ) {
			if( !resource.allRoles ) {
				if( !create ) {
					return;
				}
				resource.allRoles = {
					byPrivilegeId: {}
				};
			}

			return resource.allRoles;
		}

		const roleId = role.getId();
		if( !resource.byRoleId[roleId] ) {
			if( !create ) {
				return;
			}

			resource.byRoleId[roleId] = {
				byPrivilegeId: {}
			};
		}

		return resource.byRoleId[roleId];
	}

	isAllowed(role, resource, privilege) {
		this.isAllowedRole      = role ? this.roles.get(role) : null;
		this.isAllowedResource  = resource ? this.resources.get(resource) : null;
		this.isAllowedPrivilege = null;
		role                    = this.isAllowedRole;
		resource                = this.isAllowedResource;

		if( !privilege ) {
			do {
				let result = this.roleDFSAllPrivileges(role, resource, privilege);
				if( role && result !== undefined ) {
					return result;
				}

				let rules = this.getRules(resource, null);
				if( rules !== undefined ) {
					for( let rule in rules.byPrivilegeId ) {
						let ruleTypeOnePrivilege = this.getRuleType(resource, null, rule);
						if( this.rule.deny === ruleTypeOnePrivilege ) {
							return false;
						}
					}

					let ruleTypeAllPrivileges = this.getRuleType(resource, null, null);
					if( ruleTypeAllPrivileges ) {
						return this.rule.allow === ruleTypeAllPrivileges;
					}
				}

				let parent = this.resources.getParents(resource);
				let key    = Object.keys(parent)[0];
				resource   = parent[key];
			} while( true );
		}
		else {
			this.isAllowedPrivilege = privilege;

			do {
				let result = this.roleDFSOnePrivilege(role, resource, privilege);
				if( role && result !== undefined ) {
					return result;
				}

				let ruleType, ruleTypeAllPrivilege;
				if( (ruleType = this.getRuleType(resource, null, privilege)) !== undefined ) {
					return this.rule.allow === ruleType;
				}
				else if( (ruleTypeAllPrivilege = this.getRuleType(resource, null, null)) !== undefined ) {
					result = this.rule.allow === ruleTypeAllPrivilege;

					if( result || !resource ) {
						return result;
					}
				}

				let parent = this.resources.getParents(resource);
				let key    = Object.keys(parent)[0];
				resource   = parent[key];
			} while( true );
		}
	}

	roleDFSAllPrivileges(role, resource) {
		const dfs = {
			visited: {},
			stack: []
		};

		let result = this.roleDFSVisitAllPrivileges(role, resource, dfs);
		if( result !== undefined ) {
			return result;
		}

		while( (role = dfs.stack.shift()) ) {
			if( !dfs['visited'][role.getId()] ) {

				result = this.roleDFSVisitAllPrivileges(role, resource, dfs);
				if( result !== undefined ) {
					return result;
				}
			}
		}

		return;
	}

	roleDFSVisitAllPrivileges(role, resource, dfs) {
		if( !dfs ) {
			throw new Error(`dfs parametr may not be null`);
		}

		const rules = this.getRules(resource, role);
		if( rules !== undefined ) {
			for( let rule in rules.byPrivilegeId ) {
				if( rules.byPrivilegeId.hasOwnProperty(rule) &&
						this.rule.deny === this.getRuleType(resource, role, rules.byPrivilegeId[rule]) ) {

					return false;
				}
			}

			let allPrivilege = this.getRuleType(resource, role, null);
			if( allPrivilege !== undefined ) {
				return this.rule.allow === allPrivilege;
			}
		}

		dfs['visited'][role.getId()] = true;

		let parents = this.roles.getParents(role);
		for( var parent in parents ) {
			dfs.stack.push(parents[parent]);
		}

		return;
	}

	roleDFSOnePrivilege(role, resource, privilege) {
		if( !privilege ) {
			throw new Error(`Privilege parametr many not be null.`);
		}

		const dfs = {
			visited: {},
			stack: []
		};

		let result = this.roleDFSVisitOnePrivilege(role, resource, privilege, dfs);
		if( result !== undefined ) {
			return result;
		}

		while( (role = dfs.stack.shift()) ) {
			if( !dfs['visited'][role.getId()] ) {

				result = this.roleDFSVisitOnePrivilege(role, resource, privilege, dfs);
				if( result !== undefined ) {
					return result;
				}
			}
		}

		return;
	}

	roleDFSVisitOnePrivilege(role, resource, privilege, dfs) {
		if( !privilege ) {
			throw new Error(`Privilege parametr many not be null.`)
		}
		if( !dfs ) {
			throw new Error(`Dfs parametr many not be null.`)
		}

		let ruleTypeOnePrivilege = this.getRuleType(resource, role, privilege);
		if( ruleTypeOnePrivilege !== undefined ) {
			return this.rule.allow === ruleTypeOnePrivilege;
		}
		else if( (ruleTypeOnePrivilege = this.getRuleType(resource, role, null)) !== undefined ) {
			return this.rule.allow === ruleTypeOnePrivilege;
		}

		dfs.visited[role.getId()] = true;
		let parents               = this.roles.getR(role)['parent'];
		for( let parent in parents ) {
			dfs.stack.push(parents[parent]);
		}

		return;
	}

	getRuleType(resource, role, privilege) {
		const rules = this.getRules(resource, role);
		if( !rules ) {
			return;
		}

		let rule;
		if( !privilege ) {
			rule = rules.allPrivileges;

			if( !rule ) {
				return;
			}
		}
		else if( !rules.byPrivilegeId[privilege] ) {
			return;
		}
		else {
			rule = rules.byPrivilegeId[privilege];
		}

		let assertionValue = false;
		if( rule.assert ) {
			let assertion = rule.assert;
			// TODO:
		}

		// powinno byc jeszcze || asertionValue :)
		if( !rule.assert ) {
			return rule.type;
		}
		else if( !resource || !role || privilege ) {
			return;
		}
		else if( this.rule.allow === rule.type ) {
			return this.rule.deny;
		}

		return this.rule.allow;
	}
}

module.exports = Acl;