class backendrecord {
private:
	std::string record;
	QType type;
	uint32_t ttl = 0;
public:
	backendrecord() {

	}
	backendrecord(std::string record,QType type,uint32_t ttl) {
		this->record = record;
		this->type = type;
		this->ttl = ttl;
	}

	const std::string& getRecord() const {
		return record;
	}

	void setRecord(const std::string& record) {
		this->record = record;
	}

	QType getType() const {
		return type;
	}

	void setType(QType type) {
		this->type = type;
	}

	uint32_t getTtl() const {
		return ttl;
	}

	void setTtl(uint32_t ttl) {
		this->ttl = ttl;
	}

	~backendrecord() {

	}

};
