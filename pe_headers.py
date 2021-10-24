import csv, os, pefile
import yara
import math
import hashlib

class pe_features():
    def __init__(self, source, output, label):
        self.source = source
        self.output = output
        self.label = label
        self.rules = yara.compile(filepath='./peid.yara')
    def check_packer(self,filepath):
        result=[]
        matches = self.rules.match(filepath)

        try:
            if matches == [] or matches == {}:
                result.append([0, "NoPacker"])
            else:
                result.append([1,matches['main'][0]['rule']])
        except:
            result.append([1,matches[0]])

        return result


    def extract_all(self,filepath):
        data = []
        try:
            pe = pefile.PE(filepath)
        except Exception, e:
            print "{} while opening {}".format(e,filepath)
        else:
            data += self.extract_dos_header(pe)
            data += self.extract_file_header(pe)
            data += self.extract_optinal_header(pe)

            num_ss_nss = self.get_count_suspicious_sections(pe)
            data += num_ss_nss
            packer = self.check_packer(filepath)

            # Appending the packer info to the rest of features
            data += packer[0]
            entropy_sections = self.get_text_data_entropy(pe)
            data += entropy_sections
            f_size_entropy = self.get_file_entropy(filepath)
            data += f_size_entropy
            fileinfo = self.get_fileinfo(pe)
            data.append(fileinfo)
            data.append(self.type)

        return data

    def create_dataset(self):
        self.write_csv_header()
        count = 0

        #run through all file of source and extract features
        for file in os.listdir(self.source):
            filepath = self.source + file
            data = self.extract_all(filepath)
            hash_ = self.getMD5(filepath)
            print "hash : " , hash_
            data.insert(0, hash_)
            data.insert(0, file)

            self.write_csv_header(data)
            count += 1
            print "Succesfully Data extracted ad written for {}.".format(file)
            print "Processed " + str(count) + " files"


def main():

    source_path = raw_input("Enter the path of samples (ending with /) >> ")
    output_file = raw_input("Give file name of output file. (.csv) >>")
    label = raw_input("Enter type of sample( malware(1)|benign(0))>>")

    features = pe_features(source_path, output_file, label)
    features.create_dataset()

if __name__ == '__main__':
    main()



