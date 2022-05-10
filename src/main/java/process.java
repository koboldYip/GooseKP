import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import lombok.SneakyThrows;

import java.io.File;

public class process {

    @SneakyThrows
    public static void main(String[] args) {
        XmlMapper xmlMapper = new XmlMapper();
        GOOSE gse = new GOOSE();
        Root value = xmlMapper.readValue(new File("src/main/resources/Cfg.xml"), Root.class);
        gse.createGOOSE(value.getSenders().get(0).getDataset());
        gse.createMessage();
        gse.run();
    }
}
