import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import lombok.SneakyThrows;

import java.io.File;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class process {

    @SneakyThrows
    public static void main(String[] args) {
        XmlMapper xmlMapper = new XmlMapper();
        Root value = xmlMapper.readValue(new File("src/main/resources/Cfg.xml"), Root.class);
        GOOSE gse = new GOOSE();
        gse.createGOOSE(value.getSenders().get(0).getDataset());

        Executors.newSingleThreadScheduledExecutor().schedule(
                () -> {
                    value.getSenders().get(0).getDataset().getItems().get(0).setValue("true");
                    value.getSenders().get(0).getDataset().getItems().get(1).setValue("6");
                    value.getSenders().get(0).getDataset().getItems().get(2).setValue("6.6");
                    gse.setData(value.getSenders().get(0).getDataset());
                }
                , 10, TimeUnit.SECONDS);

        Executors.newSingleThreadScheduledExecutor().schedule(
                () -> {
                    value.getSenders().get(0).getDataset().getItems().get(0).setValue("true");
                    value.getSenders().get(0).getDataset().getItems().get(1).setValue("7");
                    value.getSenders().get(0).getDataset().getItems().get(2).setValue("7.7");
                    gse.setData(value.getSenders().get(0).getDataset());
                }
                , 20, TimeUnit.SECONDS);
    }
}
