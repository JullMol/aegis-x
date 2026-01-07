export namespace bridge {
	
	export class SecurityFinding {
	    port: number;
	    risk: string;
	    summary: string;
	    action: string;
	
	    static createFrom(source: any = {}) {
	        return new SecurityFinding(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.port = source["port"];
	        this.risk = source["risk"];
	        this.summary = source["summary"];
	        this.action = source["action"];
	    }
	}
	export class AnalysisResult {
	    findings: SecurityFinding[];
	    enriched_packets: any[];
	
	    static createFrom(source: any = {}) {
	        return new AnalysisResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.findings = this.convertValues(source["findings"], SecurityFinding);
	        this.enriched_packets = source["enriched_packets"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace scanner {
	
	export class Device {
	    ip: string;
	    mac: string;
	    hostname: string;
	
	    static createFrom(source: any = {}) {
	        return new Device(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.mac = source["mac"];
	        this.hostname = source["hostname"];
	    }
	}
	export class PortResult {
	    port: number;
	    status: string;
	    service: string;
	
	    static createFrom(source: any = {}) {
	        return new PortResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.port = source["port"];
	        this.status = source["status"];
	        this.service = source["service"];
	    }
	}

}

export namespace sniffer {
	
	export class PacketInfo {
	    timestamp: string;
	    source: string;
	    dest: string;
	    protocol: string;
	    length: number;
	    info: string;
	    payload: string;
	    location: string;
	
	    static createFrom(source: any = {}) {
	        return new PacketInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.timestamp = source["timestamp"];
	        this.source = source["source"];
	        this.dest = source["dest"];
	        this.protocol = source["protocol"];
	        this.length = source["length"];
	        this.info = source["info"];
	        this.payload = source["payload"];
	        this.location = source["location"];
	    }
	}

}

