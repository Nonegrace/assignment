import hashlib

# read and get passwords in yahoo
def read_yahoo():
	f = open("Password Dump/yahoo/password.file", "r")
	dict_password={}
	for line in f.readlines()[3500:4000]:
		try:
			password = line.split(":")[2].replace("\r", "").replace("\n", "")
			if password == "":
				continue
		except:
			continue
		else:
			dict_password[password] = line.replace("\r", "").replace("\n", "")
	return dict_password

# write passwords and original lines into file
def write_to_file(path, dict_password):
	f=open(path, "w+")
	num = 0
	for item in dict_password.keys():
		if(isinstance(dict_password[item], list)):
			for i in range(len(dict_password[item])):
				num = num+1
				string = dict_password[item][i][0] + " " + item + "\n"
				f.write(string)
				if num >= 99:
					break
		else:
			num=num+1
			string = dict_password[item] + " " + item + "\n"
			f.write(string)
		if num >= 99:
			break
		else:
			continue
	f.close()

# encrypt passwords with SHA256 and add salt both in front of and behind password
def sha_256_fs(password):
	dict_password = {}
	for item in password:
		dict_password[item] = []
		#salt = i*10+j
		for i in range(10):
			for j in range(10):
				new_item = item + str(i) + str(j)
				to_add = (hashlib.sha256(new_item).hexdigest(), "behind", str(i)+str(j))
				dict_password[item].append(to_add)
				new_item = str(i) + str(j) + item
				to_add = (hashlib.sha256(new_item).hexdigest(), "front", str(i)+str(j))
				dict_password[item].append(to_add)
	return dict_password

# encrypt passwords with SHA1
def sha_linkedin(password):
	new_password = []
	for item in password:
		item = hashlib.sha1(item).hexdigest()
		if len(item) == 40:
			new_password.append(item)
	return new_password

#get password from original files and sort password
def read_pwd_file(path):
	password = []
	f = open(path, "r")
	for item in f.readlines():
		item = item.replace("\r", "").replace("\n", "")
		password.append(item)
	f.close()
	password.sort()
	return password

# use binary search to get passwords
def get_samepwd_l(password, ciphertext):
	dict_password = {}
	encrypt_password = sha_linkedin(password)
	for i in range(len(encrypt_password)):
		low = 0
		high = len(ciphertext)-1
		while low<high:
			mid = (high+low)/2
			if (ciphertext[:5] == "00000" and encrypt_password[i][5:] == ciphertext[mid][5:]) or encrypt_password[i] == ciphertext[mid]:
			#for linkedin passwords, only compare the last 35 bits
				dict_password[password[i]] = ciphertext[mid]
				break
			elif encrypt_password[i] < ciphertext[mid]:
				high = mid-1
			else:
				low = mid+1
	return dict_password

def get_samepwd_fs(password, ciphertext):
	dict_password = {}
	encrypt_password = sha_256_fs(password)
	for item in encrypt_password.keys():
		for i in range(len(encrypt_password[item])):
			check = encrypt_password[item][i][0]
			low = 0
			high = len(ciphertext)-1
			while low<high:
				mid = (high + low)/2
				if ciphertext[mid] == check:
					if not dict_password.has_key(item):
						dict_password[item] = []
					to_add = (ciphertext[mid], encrypt_password[item][i][1], encrypt_password[item][i][2])
					dict_password[item].append(to_add)
					break
				elif check < ciphertext[mid]:
					high = mid-1
				else:
					low = mid+1
	return dict_password

# get common passwords from file downloaded
def getpwd_fromdict(file_path):
	password = []
	o = open(file_path, "r")
	for item in o.readlines():
		s = item.replace("\r", "").replace("\n","")
		password.append(s)
	o.close()
	return password

if __name__ == "__main__":
	write_to_file("yahoo password.txt", read_yahoo())
	guesspwd = getpwd_fromdict("Password Dump/pwd dictionary/passwords.txt")
	write_to_file("linkedin password.txt", get_samepwd_l(guesspwd, read_pwd_file("Password Dump/linkedin/SHA1.txt")))
	write_to_file("formspring password.txt", get_samepwd_fs(guesspwd[:50000], read_pwd_file("Password Dump/formspring/formspring.txt")))
