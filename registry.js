'use strict';
const isString   = require('../common/isString');
const isFunction = require('../common/isFunction');

class Registry {

	constructor(name, instance) {
		if( !isString(name) || !isFunction(instance) ) {
			throw TypeError(`Wrong argument type. First "name" should be string type, 
							second should be Role/Resource constructor.`);
		}
		this.Rs       = {};
		this.name     = name.substr(0, 1).toUpperCase() + name.substr(1).toLowerCase();
		this.instance = instance;
	}

	/**
	 * @param R string or role|resource instance
	 * @param parents string|array
	 * */
	add(R, parents/* = null*/) {

		if( isString(R) ) {
			R = new this.instance(R);
		}
		else if( !(R instanceof this.instance) ) {
			throw new TypeError(`add() expects first param to be instance of ${this.name}`);
		}

		var RId = R.getId();

		if( this.has(RId) ) {
			throw new Error(`${this.name} ${RId} already exist in the registry.`);
		}

		var RParents = {};

		if( parents ) {
			if( !Array.isArray(parents) ) {
				parents = [parents];
			}

			for( let i = 0; i < parents.length; i++ ) {
				try {
					var parentId = this.getRId(parents[i]);
					var RParent  = this.get(parentId);
				}
				catch( e ) {
					throw new Error(`Parent ${this.name} ${parentId} does not exist.`, e);
				}

				RParents[parentId]                 = RParent;
				this.Rs[parentId]['children'][RId] = R;
			}
		}

		this.Rs[RId] = {
			instance: R,
			parents: RParents,
			children: {}
		};

		return this;
	}

	get(R) {
		var RId = this.getRId(R);

		if( !this.has(RId) ) {
			throw new Error(`${this.name} ${RId} not found.`);
		}

		return this.Rs[RId]['instance'];
	}

	getR(R) {
		var RId = this.getRId(R);

		if( !this.has(RId) ) {
			throw new Error(`${this.name} ${RId} not found.`);
		}

		return this.Rs[RId];
	}

	has(R) {
		var RId = this.getRId(R);

		return !!this.Rs[RId];
	}

	remove(R) {
		try {
			var RId = this.get(R).getId();
		}
		catch( e ) {
			throw new Error(e);
		}

		// remove parent
		var children = this.Rs[RId]['children'];
		for( let child in children ) {
			if( children.hasOwnProperty(child) ) {
				delete this.Rs[child].parents[RId];
			}
		}

		// remove child from it's parents
		var parents = this.Rs[RId]['parents'];
		for( let parent in parents ) {
			if( this.Rs.hasOwnProperty(parent) ) {
				delete this.Rs[parent].children[RId];
			}
		}

		delete this.Rs[RId];

		return this;
	}

	getAll() {
		return this.Rs;
	}

	getRId(R) {
		return R instanceof this.instance ? R.getId() : R;
	}

	getParents(R) {
		let RId = this.getRId(R);

		return this.Rs[RId]['parents'];
	}
}

module.exports = Registry;