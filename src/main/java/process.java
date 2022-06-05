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
        Sender sender = new Sender();
        GOOSE gse = new GOOSE(value.getSenders().get(0).getDataset());
        sender.getGooseList().add(gse);

        Executors.newSingleThreadScheduledExecutor().schedule(
                () -> {
                    value.getSenders().get(0).getDataset().getItems().get(0).setValue("true");
                    value.getSenders().get(0).getDataset().getItems().get(1).setValue("228");
                    value.getSenders().get(0).getDataset().getItems().get(2).setValue("14.2");
                    sender.changeGoose(gse);
                }
                , 10, TimeUnit.SECONDS);

        sender.sender();

    }
}
